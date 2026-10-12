//! Trust records for configuration files found by directory discovery.
//!
//! A `bailey.toml` discovered by walking up from the target or the working
//! directory can have arrived with the very code bailey was asked to confine: a
//! cloned repository or an unpacked archive can carry one. Such a file
//! contributes to a policy only after the user has accepted it, and acceptance
//! is recorded against the file's contents, so that editing a trusted config
//! revokes it until it is accepted again.
//!
//! The global config, user-written profiles, and a file named with `--config`
//! need no record: the user wrote them, or typed them for this run.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Filename of the trust store within the data directory.
const STORE_NAME: &str = "trusted.toml";

/// Why a discovered config is not being applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    /// Trust has never been recorded for this file.
    Untrusted,
    /// Trust was recorded and the contents have changed since.
    Changed,
    /// The file belongs to another user, who can change it at will.
    Owned(String),
    /// Users other than the owner can write the file, so a recorded hash is a
    /// race rather than a guarantee.
    Writable(String),
    /// A directory holding the file can be written by someone else, who can
    /// replace the file by renaming over it whatever its own mode says.
    WritableParent { dir: String, who: String },
    /// The file could not be read in order to check it.
    Unreadable(String),
    /// The trust store itself cannot be read from where this run is standing,
    /// so nothing can be said about whether the file was accepted.
    StoreUnreachable,
}

impl Rejected {
    /// A short word for a listing.
    pub fn word(&self) -> &'static str {
        match self {
            Rejected::Untrusted => "untrusted",
            Rejected::Changed => "changed",
            Rejected::Owned(_) => "not yours",
            Rejected::Writable(_) => "writable",
            Rejected::WritableParent { .. } => "exposed",
            Rejected::Unreadable(_) => "unreadable",
            Rejected::StoreUnreachable => "unknown",
        }
    }

    /// Why the file was not applied, as a sentence fragment.
    pub fn reason(&self) -> String {
        match self {
            Rejected::Untrusted => "you have not trusted it".into(),
            Rejected::Changed => "it changed since you trusted it".into(),
            Rejected::Owned(owner) => format!("it is owned by {owner}, not by you"),
            Rejected::Writable(who) => format!("it is writable by {who}"),
            Rejected::WritableParent { dir, who } => {
                format!("{dir} can be written by {who}, who could replace it")
            }
            Rejected::Unreadable(err) => format!("it could not be read: {err}"),
            Rejected::StoreUnreachable => "the trust store is not reachable from \
                 inside a sandbox, so nothing here is known to be trusted"
                .into(),
        }
    }

    /// What the user can do about it, if anything.
    pub fn remedy(&self, path: &Path) -> Option<String> {
        match self {
            Rejected::Untrusted => Some(format!("bailey trust {}", path.display())),
            Rejected::Changed => Some(format!(
                "review the change, then run: bailey trust {}",
                path.display()
            )),
            Rejected::Writable(_) => Some(format!("chmod go-w {}", path.display())),
            Rejected::WritableParent { dir, .. } => Some(format!("chmod go-w {dir}")),
            // Deliberately no remedy: `bailey trust` from in here would write a
            // record into a private home that is discarded when the run ends,
            // which would look like it worked.
            Rejected::Owned(_) | Rejected::Unreadable(_) | Rejected::StoreUnreachable => None,
        }
    }
}

/// The set of config files the user has accepted.
#[derive(Debug)]
pub struct Store {
    entries: BTreeMap<PathBuf, String>,
    /// Whether the store could be read at all. A store that is simply absent is
    /// reachable and empty; one that cannot be reached from inside a sandbox is
    /// a different answer, and saying "you have not trusted this" there would be
    /// a claim bailey cannot support.
    reachable: bool,
}

impl Default for Store {
    fn default() -> Self {
        Store {
            entries: BTreeMap::new(),
            reachable: true,
        }
    }
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct StoreFile {
    #[serde(default)]
    trusted: BTreeMap<String, String>,
}

/// Write a file only its owner can read, creating it and nothing else.
///
/// The file is created rather than opened: `O_EXCL` makes the create fail when
/// the path is occupied by anything at all, including a symlink, and
/// `O_NOFOLLOW` closes the window where the final component is replaced between
/// a failed create and the next attempt. Writing through a path bailey did not
/// create is how the store's bytes land in a file somebody else chose, and the
/// rename that follows would then carry that content over the store.
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(text.as_bytes())
}

impl Store {
    /// Read the store from the user's data directory.
    ///
    /// A missing store is an empty one, so a first run needs no setup.
    pub fn load() -> Store {
        match store_path() {
            Some(path) if path.exists() => Store::load_from(&path),
            // Inside a sandbox the data directory is the private home, so the
            // user's store is not there and cannot be. Reading that as "nothing
            // is trusted" would report every discovered config as unaccepted.
            _ if crate::backend::world::inside_sandbox() => Store {
                reachable: false,
                ..Store::default()
            },
            _ => Store::default(),
        }
    }

    /// Read the store from an explicit path.
    pub fn load_from(path: &Path) -> Store {
        let Ok(text) = fs::read_to_string(path) else {
            return Store::default();
        };
        match toml::from_str::<StoreFile>(&text) {
            Ok(file) => Store {
                entries: file
                    .trusted
                    .into_iter()
                    .map(|(path, digest)| (PathBuf::from(path), digest))
                    .collect(),
                reachable: true,
            },
            Err(err) => {
                // Reading an unparseable store as empty would quietly drop
                // every config the user had accepted.
                eprintln!(
                    "bailey: warning: ignoring the trust store `{}`: {err}",
                    path.display()
                );
                Store::default()
            }
        }
    }

    /// Write the store to the user's data directory.
    pub fn save(&self) -> Result<(), String> {
        let path = store_path().ok_or_else(|| {
            "no data directory: set XDG_DATA_HOME or HOME to record trust".to_owned()
        })?;
        self.save_to(&path)
    }

    /// Write the store to an explicit path, replacing it atomically.
    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        let file = StoreFile {
            trusted: self
                .entries
                .iter()
                .map(|(path, digest)| (path.display().to_string(), digest.clone()))
                .collect(),
        };
        let text = toml::to_string_pretty(&file).map_err(|err| err.to_string())?;

        if let Some(parent) = path.parent() {
            use std::os::unix::fs::DirBuilderExt;
            // A store another local user can write is not a record of what
            // this user trusts.
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .or_else(|err| {
                    if err.kind() == std::io::ErrorKind::AlreadyExists {
                        Ok(())
                    } else {
                        Err(err)
                    }
                })
                .map_err(|err| format!("could not create `{}`: {err}", parent.display()))?;
        }
        let staging = path.with_extension("toml.new");
        write_private(&staging, &text).map_err(|err| match err.kind() {
            std::io::ErrorKind::AlreadyExists => format!(
                "`{}` is already occupied; another process may be writing the \
                     trust store, or a file has been left where bailey stages its \
                     writes",
                staging.display()
            ),
            _ => format!("could not write `{}`: {err}", staging.display()),
        })?;
        fs::rename(&staging, path)
            .map_err(|err| format!("could not replace `{}`: {err}", path.display()))
    }

    /// Whether `path` may contribute to a policy, and why not when it may not.
    ///
    /// The bytes read here are the bytes the digest was computed from, and they
    /// are returned so a caller can apply exactly those rather than read the
    /// file a second time. A second read is a second chance for the file to
    /// change, and the policy would then be built from bytes no digest ever
    /// covered.
    pub fn check(&self, path: &Path) -> Option<Rejected> {
        self.check_read(path).0
    }

    /// [`Store::check`], with the bytes it read when the file may contribute.
    pub fn check_read(&self, path: &Path) -> (Option<Rejected>, Vec<u8>) {
        if !self.reachable {
            return (Some(Rejected::StoreUnreachable), Vec::new());
        }
        let path = absolute(path);
        let meta = match fs::metadata(&path) {
            Ok(meta) => meta,
            Err(err) => return (Some(Rejected::Unreadable(err.to_string())), Vec::new()),
        };
        // Ownership is re-checked here, not only when trust was recorded: a
        // file that became writable by others since then is no longer covered
        // by the hash that was stored for it.
        if let Some(exposure) = exposure(&meta) {
            return (Some(exposure), Vec::new());
        }
        // A file nobody else may write still sits somewhere, and a directory
        // another user may write is one they can rename a file out of and a
        // file of their own into. The mode on the file says nothing about that.
        if let Some(exposure) = exposed_parents(&path) {
            return (Some(exposure), Vec::new());
        }
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => return (Some(Rejected::Unreadable(err.to_string())), Vec::new()),
        };
        let digest = digest_of(&bytes);
        let verdict = match self.entries.get(&path) {
            Some(recorded) if *recorded == digest => None,
            Some(_) => Some(Rejected::Changed),
            None => Some(Rejected::Untrusted),
        };
        (verdict, bytes)
    }

    /// Record trust in `path` as it currently reads.
    pub fn record(&mut self, path: &Path) -> Result<PathBuf, String> {
        if !self.reachable {
            return Err(
                "the trust store is not reachable from inside a sandbox: a record \
                 written here would go into a private home that is discarded when \
                 the run ends. Trust the file from outside the sandbox."
                    .into(),
            );
        }
        let path = absolute(path);
        let meta = fs::metadata(&path)
            .map_err(|err| format!("could not read `{}`: {err}", path.display()))?;
        if !meta.is_file() {
            return Err(format!("`{}` is not a file", path.display()));
        }
        if let Some(exposure) = exposure(&meta) {
            let mut message = format!(
                "refusing to trust `{}`: {}, so its contents could change after \
                 you accepted them",
                path.display(),
                exposure.reason()
            );
            if let Some(remedy) = exposure.remedy(&path) {
                message.push_str(&format!("; {remedy}"));
            }
            return Err(message);
        }
        if let Some(exposure) = exposed_parents(&path) {
            let mut message = format!(
                "refusing to trust `{}`: {}, so its contents could change after \
                 you accepted them",
                path.display(),
                exposure.reason()
            );
            if let Some(remedy) = exposure.remedy(&path) {
                message.push_str(&format!("; {remedy}"));
            }
            return Err(message);
        }
        let digest = digest(&path).map_err(|err| err.to_string())?;
        self.entries.insert(path.clone(), digest);
        Ok(path)
    }

    /// Revoke trust in `path`. Returns whether there was anything to revoke.
    pub fn forget(&mut self, path: &Path) -> bool {
        self.entries.remove(&absolute(path)).is_some()
    }

    /// Every trusted path, with its current status, in path order.
    pub fn listing(&self) -> Vec<(PathBuf, Option<Rejected>)> {
        self.entries
            .keys()
            .map(|path| (path.clone(), self.check(path)))
            .collect()
    }
}

/// Where the trust store lives.
pub fn store_path() -> Option<PathBuf> {
    // Inside a sandbox, `HOME` is the private home: a directory the target is
    // granted read-write and that persists between runs. A store read from
    // there is one the target could have written, naming a config it also
    // wrote, so a nested run would apply a policy nobody ever accepted. There
    // is no store to read in here.
    if crate::backend::world::inside_sandbox() {
        return None;
    }
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME")
        && !dir.is_empty()
    {
        // A relative value would resolve against the working directory, which
        // is where a project, and anything it contains, lives.
        let dir = Path::new(&dir);
        if dir.is_absolute() {
            return Some(dir.join("bailey").join(STORE_NAME));
        }
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .map(|home| home.join(".local/share/bailey").join(STORE_NAME))
}

/// Whether `path` or any directory holding it can be changed by someone other
/// than the running user.
///
/// The same question `trust` asks of a discovered config, asked of files that
/// need no trust record: a profile and the global config are the user's own, but
/// "in your config directory" is a claim about provenance, not about who can
/// write there now.
pub fn exposure_of(path: &Path) -> Option<Rejected> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) => return Some(Rejected::Unreadable(err.to_string())),
    };
    exposure(&meta).or_else(|| exposed_parents(path))
}

/// Report how a file can be changed by someone other than the running user.
/// Whether any directory holding `path` can be written by someone else.
///
/// The parent chain is resolved through symlinks before the walk, so every
/// directory in the resolved chain is judged by the metadata of the one that
/// actually holds the next component, and a rejection names that real
/// directory. The chain as typed is not walked as well: the kernel traverses
/// both halves, and the half that holds a symlink is left unjudged, which is a
/// gap this walk shares with the one it replaced. Walked upwards to the root.
/// A sticky directory is not counted: `/tmp` is world-writable by design, and
/// the sticky bit is what stops one user replacing another's entry there.
fn exposed_parents(path: &Path) -> Option<Rejected> {
    let parent = path.parent()?;
    let Ok(resolved) = fs::canonicalize(parent) else {
        return None;
    };
    let me = unsafe { libc::geteuid() };
    let mut current = Some(resolved.as_path());
    while let Some(dir) = current {
        let Ok(meta) = fs::metadata(dir) else {
            return None;
        };
        let mode = meta.mode();
        let sticky = mode & 0o1000 != 0;
        if !sticky {
            let who = if meta.uid() != me && meta.uid() != 0 {
                Some(owner(meta.uid()))
            } else if mode & 0o002 != 0 {
                Some("any user".to_string())
            } else if mode & 0o020 != 0 {
                Some(format!("group {}", group(meta.gid())))
            } else {
                None
            };
            if let Some(who) = who {
                return Some(Rejected::WritableParent {
                    dir: dir.display().to_string(),
                    who,
                });
            }
        }
        current = dir.parent();
    }
    None
}

fn exposure(meta: &fs::Metadata) -> Option<Rejected> {
    // SAFETY: `geteuid` reads the calling process's effective user id and
    // cannot fail.
    let me = unsafe { libc::geteuid() };
    if meta.uid() != me {
        return Some(Rejected::Owned(owner(meta.uid())));
    }
    let mode = meta.mode();
    if mode & 0o002 != 0 {
        return Some(Rejected::Writable("any user".into()));
    }
    if mode & 0o020 != 0 {
        return Some(Rejected::Writable(format!("group {}", group(meta.gid()))));
    }
    None
}

fn owner(uid: u32) -> String {
    // SAFETY: `getpwuid` returns a pointer to storage owned by libc, which is
    // read and copied here before anything else can call into it.
    unsafe {
        let entry = libc::getpwuid(uid);
        if entry.is_null() {
            return format!("uid {uid}");
        }
        std::ffi::CStr::from_ptr((*entry).pw_name)
            .to_string_lossy()
            .into_owned()
    }
}

fn group(gid: u32) -> String {
    // SAFETY: as `owner`, for the group database.
    unsafe {
        let entry = libc::getgrgid(gid);
        if entry.is_null() {
            return format!("gid {gid}");
        }
        std::ffi::CStr::from_ptr((*entry).gr_name)
            .to_string_lossy()
            .into_owned()
    }
}

/// Hash a file's contents.
///
/// The hash is what trust is recorded against. A modification time would be
/// cheaper and would also be forgeable, and would change for reasons that have
/// nothing to do with what the file says.
fn digest(path: &Path) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(digest_of(&bytes))
}

/// The digest of bytes already read, so one read serves both the hash and the
/// policy.
fn digest_of(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn config(dir: &Path, text: &str) -> PathBuf {
        let path = dir.join("bailey.toml");
        fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn a_recorded_file_verifies_and_an_edited_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = config(dir.path(), "[filesystem]\nread = [\"/a\"]\n");

        let mut store = Store::default();
        assert_eq!(store.check(&path), Some(Rejected::Untrusted));

        store.record(&path).unwrap();
        assert_eq!(store.check(&path), None);

        fs::write(&path, "[filesystem]\nread = [\"/\"]\n").unwrap();
        assert_eq!(store.check(&path), Some(Rejected::Changed));

        fs::write(&path, "[filesystem]\nread = [\"/a\"]\n").unwrap();
        assert_eq!(
            store.check(&path),
            None,
            "restoring the trusted contents restores trust"
        );
    }

    #[test]
    fn the_store_round_trips_through_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = config(dir.path(), "[filesystem]\nread = [\"/a\"]\n");
        let store_file = dir.path().join("state/trusted.toml");

        let mut store = Store::default();
        store.record(&path).unwrap();
        store.save_to(&store_file).unwrap();

        let reloaded = Store::load_from(&store_file);
        assert_eq!(reloaded.check(&path), None);
        assert_eq!(reloaded.listing().len(), 1);
    }

    #[test]
    fn a_missing_store_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::load_from(&dir.path().join("nothing-here.toml"));
        assert!(store.listing().is_empty());
    }

    #[test]
    fn forgetting_revokes_trust() {
        let dir = tempfile::tempdir().unwrap();
        let path = config(dir.path(), "[filesystem]\nread = [\"/a\"]\n");

        let mut store = Store::default();
        store.record(&path).unwrap();
        assert!(store.forget(&path));
        assert_eq!(store.check(&path), Some(Rejected::Untrusted));
        assert!(!store.forget(&path), "revoking twice reports nothing to do");
    }

    #[test]
    fn a_world_writable_config_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = config(dir.path(), "[filesystem]\nread = [\"/a\"]\n");

        let mut store = Store::default();
        store.record(&path).unwrap();
        assert_eq!(store.check(&path), None);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let rejected = store.check(&path).expect("a world-writable config");
        assert!(matches!(rejected, Rejected::Writable(_)), "{rejected:?}");
        assert!(rejected.reason().contains("any user"));

        assert!(
            store.record(&path).is_err(),
            "and it cannot be trusted again while it stays that way"
        );
    }

    #[test]
    fn a_group_writable_config_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = config(dir.path(), "[filesystem]\nread = [\"/a\"]\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();

        let mut store = Store::default();
        let err = store.record(&path).expect_err("a group-writable config");
        assert!(err.contains("group"), "{err}");
        assert!(err.contains("chmod go-w"), "the fix is named: {err}");
    }

    #[test]
    fn a_config_owned_by_another_user_is_refused() {
        // Root owns this and the test does not run as root, which is the
        // situation the check exists for. Running as root makes the check
        // vacuous, so there is nothing to assert.
        // SAFETY: `geteuid` cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let mut store = Store::default();
        let err = store
            .record(Path::new("/etc/passwd"))
            .expect_err("a file owned by root");
        assert!(err.contains("root") || err.contains("uid 0"), "{err}");
    }

    #[test]
    fn a_missing_file_is_unreadable_rather_than_untrusted() {
        let dir = tempfile::tempdir().unwrap();
        let path = config(dir.path(), "[filesystem]\nread = [\"/a\"]\n");
        let mut store = Store::default();
        store.record(&path).unwrap();
        fs::remove_file(&path).unwrap();

        let rejected = store.check(&path).expect("a deleted config");
        assert_eq!(rejected.word(), "unreadable");
    }

    fn store_trusting(dir: &Path) -> Store {
        let mut store = Store::default();
        store
            .record(&config(dir, "[filesystem]\nread = [\"/a\"]\n"))
            .unwrap();
        store
    }

    #[test]
    fn the_staging_file_is_created_exclusively() {
        // A symlink at the staging path: the store's bytes would land at
        // whatever the link names, and the rename would move the link itself
        // over the store.
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, "a file the user owns\n").unwrap();
        std::os::unix::fs::symlink(&victim, state.join("trusted.toml.new")).unwrap();

        let store_file = state.join("trusted.toml");
        let err = store_trusting(dir.path())
            .save_to(&store_file)
            .expect_err("a symlink at the staging path");
        assert!(err.contains("already occupied"), "{err}");
        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "a file the user owns\n",
            "the store's bytes are not written through the link"
        );
        assert!(!store_file.exists(), "and the store is not replaced");
        drop(dir);

        // A regular file at the staging path: a leftover from a crashed run is
        // refused rather than overwritten.
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        let staging = state.join("trusted.toml.new");
        fs::write(&staging, "a leftover from a crashed run\n").unwrap();

        let store_file = state.join("trusted.toml");
        let err = store_trusting(dir.path())
            .save_to(&store_file)
            .expect_err("a file at the staging path");
        assert!(err.contains("already occupied"), "{err}");
        assert!(
            err.contains(&*staging.display().to_string()),
            "the staging path is named: {err}"
        );
        assert_eq!(
            fs::read_to_string(&staging).unwrap(),
            "a leftover from a crashed run\n",
            "the planted file is left as it was"
        );
        assert!(!store_file.exists(), "and the store is not replaced");
    }

    #[test]
    fn a_free_staging_path_writes_a_store_only_its_owner_can_read() {
        let dir = tempfile::tempdir().unwrap();
        let store_file = dir.path().join("state/trusted.toml");

        store_trusting(dir.path()).save_to(&store_file).unwrap();

        let mode = fs::metadata(&store_file).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "the store is private: {mode:o}");
        let reloaded = Store::load_from(&store_file);
        assert_eq!(reloaded.listing().len(), 1);
        assert_eq!(
            reloaded.check(&config(dir.path(), "[filesystem]\nread = [\"/a\"]\n")),
            None,
            "the recorded entry survived the round trip"
        );
    }

    #[test]
    fn a_second_save_finds_the_staging_path_free() {
        let dir = tempfile::tempdir().unwrap();
        let store_file = dir.path().join("state/trusted.toml");
        let store = store_trusting(dir.path());

        store.save_to(&store_file).unwrap();
        store.save_to(&store_file).unwrap();

        assert!(!store_file.with_extension("toml.new").exists());
        assert_eq!(Store::load_from(&store_file).listing().len(), 1);
    }

    #[test]
    fn a_missing_parent_directory_is_created_private() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("state/nested");
        let store_file = parent.join("trusted.toml");

        store_trusting(dir.path()).save_to(&store_file).unwrap();

        let mode = fs::metadata(&parent).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o700, "the directory is private: {mode:o}");
        assert_eq!(Store::load_from(&store_file).listing().len(), 1);
    }

    #[test]
    fn a_config_reached_through_a_symlinked_parent_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        let inner = elsewhere.join("inner");
        fs::create_dir_all(&inner).unwrap();
        let path = config(&inner, "[filesystem]\nread = [\"/a\"]\n");
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o770)).unwrap();
        let resolved = fs::canonicalize(&elsewhere).unwrap().display().to_string();

        // The direct spelling walks the real chain, and `elsewhere` is
        // group-writable.
        let rejected = Store::default()
            .check(&path)
            .expect("the direct spelling has an exposed parent");
        assert!(
            matches!(rejected, Rejected::WritableParent { .. }),
            "{rejected:?}"
        );

        // The same file through a link to `inner`: the walk must judge the
        // resolved chain, where `elsewhere` is group-writable, and not stop at
        // the destination of the first component. Trust is recorded while the
        // chain is private, and the directory is exposed afterwards.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&inner, &link).unwrap();
        let through = link.join("bailey.toml");
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = Store::default();
        store.record(&through).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o770)).unwrap();
        let rejected = store
            .check(&through)
            .expect("the real parent of the config is group-writable");
        let Rejected::WritableParent { dir: named, who } = rejected else {
            panic!("expected a writable parent, got {rejected:?}");
        };
        assert_eq!(named, resolved, "the refusal names the resolved directory");
        assert!(who.starts_with("group "), "{who}");
    }

    #[test]
    fn a_record_refuses_a_directory_the_next_run_would_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let held = dir.path().join("held");
        fs::create_dir(&held).unwrap();
        let path = config(&held, "[filesystem]\nread = [\"/a\"]\n");
        fs::set_permissions(&held, fs::Permissions::from_mode(0o770)).unwrap();
        let resolved = fs::canonicalize(&held).unwrap().display().to_string();

        let mut store = Store::default();
        let err = store.record(&path).expect_err("a group-writable parent");
        assert!(
            err.contains(&resolved),
            "the refusal names the directory: {err}"
        );
        assert!(err.contains("chmod go-w"), "the fix is named: {err}");
        assert!(!store.entries.contains_key(&path), "nothing was recorded");

        // The same file behind a private directory is recorded, and the next
        // run applies it.
        fs::set_permissions(&held, fs::Permissions::from_mode(0o700)).unwrap();
        store.record(&path).unwrap();
        assert_eq!(store.check(&path), None);

        // A file that is itself exposed is reported for itself, even when its
        // directory is exposed too.
        fs::set_permissions(&held, fs::Permissions::from_mode(0o770)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let err = store.record(&path).expect_err("a world-writable config");
        assert!(err.contains("it is writable by any user"), "{err}");
    }

    #[test]
    fn an_exposure_of_reports_the_parent() {
        let dir = tempfile::tempdir().unwrap();
        let held = dir.path().join("held");
        fs::create_dir(&held).unwrap();
        let path = config(&held, "[filesystem]\nread = [\"/a\"]\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&held, fs::Permissions::from_mode(0o770)).unwrap();

        let rejected = exposure_of(&path).expect("the parent is group-writable");
        let Rejected::WritableParent { dir: named, who } = rejected else {
            panic!("expected a writable parent, got {rejected:?}");
        };
        assert_eq!(
            named,
            fs::canonicalize(&held).unwrap().display().to_string(),
            "the refusal names the resolved directory"
        );
        assert!(who.starts_with("group "), "{who}");

        fs::set_permissions(&held, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(exposure_of(&path), None, "a private chain is no exposure");
    }
}
