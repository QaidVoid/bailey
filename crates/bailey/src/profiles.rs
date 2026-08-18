//! Bundled starting profiles.
//!
//! A profile is a named TOML config fragment. Bailey ships several, and a user
//! can write their own in `$XDG_CONFIG_HOME/bailey/profiles/<name>.toml`, which
//! is how a per-program policy becomes reusable across directories. The
//! [`UNTRUSTED`] profile is the safe deny-by-default floor applied to every run;
//! other profiles layer additively on top of it. Users extend a profile with
//! their own per-directory and per-game config.

use std::path::{Path, PathBuf};

/// The minimal deny-by-default base applied to every run.
pub const UNTRUSTED: &str = include_str!("profiles/untrusted.toml");

/// Additive profile for native Linux games (GPU, audio, display, fonts).
pub const NATIVE_GAME: &str = include_str!("profiles/native-game.toml");

/// Additive profile for a desktop application (display, audio, fonts).
pub const DESKTOP_APP: &str = include_str!("profiles/desktop-app.toml");

/// Additive profile for a tool confined to one project directory.
pub const AI_AGENT: &str = include_str!("profiles/ai-agent.toml");

/// Additive profile for a tool that only fetches over the network.
pub const NETWORK_CLIENT: &str = include_str!("profiles/network-client.toml");

/// A bundled profile with its name and description.
pub struct Profile {
    /// The name used to select the profile.
    pub name: &'static str,
    /// A one-line description.
    pub description: &'static str,
    /// The profile's TOML source.
    pub toml: &'static str,
}

/// The name of the default base profile.
pub const DEFAULT: &str = "untrusted";

/// All bundled profiles.
pub const ALL: &[Profile] = &[
    Profile {
        name: "untrusted",
        description: "Minimal deny-by-default base: run a binary, nothing else",
        toml: UNTRUSTED,
    },
    Profile {
        name: "native-game",
        description: "Native Linux game: GPU including NVIDIA, audio, controllers, display, fonts",
        toml: NATIVE_GAME,
    },
    Profile {
        name: "desktop-app",
        description: "Desktop application: display, audio, fonts and icons, no controllers",
        toml: DESKTOP_APP,
    },
    Profile {
        name: "ai-agent",
        description: "A tool confined to its working directory: no home, no network, no devices",
        toml: AI_AGENT,
    },
    Profile {
        name: "network-client",
        description: "A tool that only fetches: outbound TCP on 443 and the certificates for it",
        toml: NETWORK_CLIENT,
    },
];

/// Look up a bundled profile by name.
pub fn get(name: &str) -> Option<&'static Profile> {
    ALL.iter().find(|profile| profile.name == name)
}

/// Where a profile's rules came from.
pub enum Source {
    /// One of the profiles shipped with bailey.
    Bundled(&'static Profile),
    /// A file the user wrote.
    User {
        /// Where it lives.
        path: PathBuf,
        /// Its contents.
        toml: String,
    },
}

impl Source {
    /// The profile's rules.
    pub fn toml(&self) -> &str {
        match self {
            Source::Bundled(profile) => profile.toml,
            Source::User { toml, .. } => toml,
        }
    }
}

/// A config layer contributed by a profile.
#[derive(Debug)]
pub struct Layer {
    /// Where the layer came from, for error messages.
    pub label: String,
    /// The layer's rules.
    pub toml: String,
}

/// The directory user-written profiles live in.
pub fn user_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME")
        && !dir.is_empty()
    {
        return Some(Path::new(&dir).join("bailey").join("profiles"));
    }
    std::env::var_os("HOME").map(|home| Path::new(&home).join(".config/bailey/profiles"))
}

/// User-written profiles, by name, sorted.
///
/// A file whose name collides with a bundled profile is not listed: the bundled
/// one wins, so listing it would suggest otherwise.
pub fn user_profiles() -> Vec<(String, PathBuf)> {
    let Some(dir) = user_dir() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut found: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_stem()?.to_str()?.to_owned();
            (path.extension()? == "toml" && get(&name).is_none()).then_some((name, path))
        })
        .collect();
    found.sort();
    found
}

/// The profile that claims `target`, if a user profile does.
///
/// A profile claims targets by listing them in `applies_to`, either by file name
/// or by absolute path. This is what makes a per-program policy reusable across
/// directories without an alias, and an explicit `--profile` always overrides it.
pub fn for_target(target: &Path) -> Result<Option<String>, String> {
    let name = target.file_name().and_then(|name| name.to_str());
    let mut claimed: Vec<String> = Vec::new();

    for (profile, path) in user_profiles() {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let declared: Claims = match toml::from_str(&text) {
            Ok(claims) => claims,
            // A profile that does not parse is reported when it is selected, not
            // while deciding whether it applies.
            Err(_) => continue,
        };
        let matches = declared.applies_to.iter().any(|claim| {
            if claim.contains('/') {
                Path::new(claim) == target
            } else {
                Some(claim.as_str()) == name
            }
        });
        if matches {
            claimed.push(profile);
        }
    }

    match claimed.len() {
        0 => Ok(None),
        1 => Ok(claimed.pop()),
        _ => Err(format!(
            "profiles {} all claim `{}`; give one `--profile` explicitly or narrow their `applies_to`",
            claimed.join(", "),
            target.display()
        )),
    }
}

#[derive(serde::Deserialize)]
struct Claims {
    #[serde(default)]
    applies_to: Vec<String>,
}

/// Find a profile by name, preferring the bundled ones.
///
/// Bundled names are reserved. A user file that shadows one is ignored with a
/// warning rather than silently replacing it, because `--profile untrusted`
/// meaning something other than the safe floor is not a surprise anyone wants.
pub fn source(name: &str) -> Result<Source, String> {
    if let Some(bundled) = get(name) {
        warn_if_shadowing(name);
        return Ok(Source::Bundled(bundled));
    }

    let Some(path) = user_path(name) else {
        return Err(unknown(name));
    };
    let toml = std::fs::read_to_string(&path)
        .map_err(|err| format!("could not read profile `{}`: {err}", path.display()))?;
    Ok(Source::User { path, toml })
}

/// Report a user file that cannot take effect because the name is bundled.
fn warn_if_shadowing(name: &str) {
    if get(name).is_some() && user_path(name).is_some() {
        eprintln!(
            "bailey: warning: a profile named `{name}` is bundled with bailey, so \
             the file of that name in your profiles directory is ignored; rename \
             it to use it"
        );
    }
}

fn user_path(name: &str) -> Option<PathBuf> {
    if name.contains('/') || name.contains('\\') {
        return None;
    }
    let path = user_dir()?.join(format!("{name}.toml"));
    path.is_file().then_some(path)
}

fn unknown(name: &str) -> String {
    let mut message = format!("unknown profile `{name}`; bundled profiles are ");
    message.push_str(
        &ALL.iter()
            .map(|profile| profile.name)
            .collect::<Vec<_>>()
            .join(", "),
    );
    if let Some(dir) = user_dir() {
        message.push_str(&format!(
            ". Write your own as {}/{name}.toml",
            dir.display()
        ));
    }
    message
}

/// Build the base layers for `profile`, lowest precedence first.
///
/// The untrusted floor is always included; any other profile is layered on top
/// of it. Returns an error message if the named profile is unknown.
pub fn base_layers(profile: &str) -> Result<Vec<Layer>, String> {
    // The floor is bundled and always applied, so a file that shadows a bundled
    // name is reported here rather than only when the name is layered.
    warn_if_shadowing(profile);
    let mut layers = vec![Layer {
        label: "profile:untrusted".into(),
        toml: UNTRUSTED.into(),
    }];
    if profile != DEFAULT {
        let source = source(profile)?;
        let label = match &source {
            Source::Bundled(_) => format!("profile:{profile}"),
            Source::User { path, .. } => path.display().to_string(),
        };
        layers.push(Layer {
            label,
            toml: source.toml().to_owned(),
        });
    }
    Ok(layers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_profile_parses_and_layers() {
        for profile in ALL {
            let layers = base_layers(profile.name).expect("a known profile");
            let borrowed: Vec<(&str, &str)> = layers
                .iter()
                .map(|layer| (layer.label.as_str(), layer.toml.as_str()))
                .collect();
            crate::config::resolve_with_bases(&borrowed, std::path::Path::new("/bin/true"), None)
                .unwrap_or_else(|err| panic!("profile `{}` does not resolve: {err}", profile.name));
        }
    }

    #[test]
    fn an_unknown_profile_names_the_alternatives() {
        let err = base_layers("no-such-profile").unwrap_err();
        assert!(err.contains("untrusted"), "{err}");
        assert!(err.contains("profiles"), "{err}");
    }

    #[test]
    fn a_user_profile_is_found_and_layered() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = dir.path().join("bailey/profiles");
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::write(
            profiles.join("mine.toml"),
            "[filesystem]\nread = [\"/opt/mine\"]\n",
        )
        .unwrap();
        unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path()) };

        let layers = base_layers("mine").expect("a user profile");
        assert_eq!(layers.len(), 2, "the floor plus the user profile");
        assert!(layers[1].toml.contains("/opt/mine"));
        assert!(layers[1].label.ends_with("mine.toml"));

        assert!(user_profiles().iter().any(|(name, _)| name == "mine"));
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }
}
