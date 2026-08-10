//! Bundled starting profiles.
//!
//! A profile is a named TOML config fragment shipped with bailey. The
//! [`UNTRUSTED`] profile is the safe deny-by-default floor applied to every run;
//! other profiles layer additively on top of it. Users extend a profile with
//! their own per-directory and per-game config.

/// The minimal deny-by-default base applied to every run.
pub const UNTRUSTED: &str = include_str!("profiles/untrusted.toml");

/// Additive profile for native Linux games (GPU, audio, display, fonts).
pub const NATIVE_GAME: &str = include_str!("profiles/native-game.toml");

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
        description: "Native Linux game: adds GPU, audio, display, and fonts",
        toml: NATIVE_GAME,
    },
];

/// Look up a bundled profile by name.
pub fn get(name: &str) -> Option<&'static Profile> {
    ALL.iter().find(|profile| profile.name == name)
}

/// Build the base layers for `profile`, lowest precedence first.
///
/// The untrusted floor is always included; a non-default profile is layered on
/// top of it. Returns an error message if the named profile is unknown.
pub fn base_layers(profile: &str) -> Result<Vec<(&'static str, &'static str)>, String> {
    let mut layers = vec![("profile:untrusted", UNTRUSTED)];
    if profile != DEFAULT {
        let found = get(profile).ok_or_else(|| format!("unknown profile `{profile}`"))?;
        layers.push((leak_label(found.name), found.toml));
    }
    Ok(layers)
}

fn leak_label(name: &str) -> &'static str {
    // Base labels appear only in error messages. The set of profile names is
    // fixed and tiny, so match them to their static strings.
    match name {
        "untrusted" => "profile:untrusted",
        "native-game" => "profile:native-game",
        _ => "profile:custom",
    }
}
