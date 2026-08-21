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
            fs::create_dir_all(parent)
                .map_err(|err| format!("could not create `{}`: {err}", parent.display()))?;
        }
        let staging = path.with_extension("toml.new");
        fs::write(&staging, text)
            .map_err(|err| format!("could not write `{}`: {err}", staging.display()))?;
        fs::rename(&staging, path)
            .map_err(|err| format!("could not replace `{}`: {err}", path.display()))
    }

    /// Whether `path` may contribute to a policy, and why not when it may not.
    pub fn check(&self, path: &Path) -> Option<Rejected> {
        if !self.reachable {
            return Some(Rejected::StoreUnreachable);
        }
        let path = absolute(path);
        let meta = match fs::metadata(&path) {
            Ok(meta) => meta,
            Err(err) => return Some(Rejected::Unreadable(err.to_string())),
        };
        // Ownership is re-checked here, not only when trust was recorded: a
        // file that became writable by others since then is no longer covered
        // by the hash that was stored for it.
        if let Some(exposure) = exposure(&meta) {
            return Some(exposure);
        }
        let digest = match digest(&path) {
            Ok(digest) => digest,
            Err(err) => return Some(Rejected::Unreadable(err.to_string())),
        };
        match self.entries.get(&path) {
            Some(recorded) if *recorded == digest => None,
            Some(_) => Some(Rejected::Changed),
            None => Some(Rejected::Untrusted),
        }
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
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME")
        && !dir.is_empty()
    {
        return Some(Path::new(&dir).join("bailey").join(STORE_NAME));
    }
    std::env::var_os("HOME").map(|home| {
        Path::new(&home)
            .join(".local/share/bailey")
            .join(STORE_NAME)
    })
}

/// Report how a file can be changed by someone other than the running user.
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
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
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
}
