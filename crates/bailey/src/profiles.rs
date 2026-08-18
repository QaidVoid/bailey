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
        "desktop-app" => "profile:desktop-app",
        "ai-agent" => "profile:ai-agent",
        "network-client" => "profile:network-client",
        _ => "profile:custom",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_profile_parses_and_layers() {
        for profile in ALL {
            let layers = base_layers(profile.name).expect("a known profile");
            crate::config::resolve_with_bases(&layers, std::path::Path::new("/bin/true"), None)
                .unwrap_or_else(|err| panic!("profile `{}` does not resolve: {err}", profile.name));
        }
    }

    #[test]
    fn the_working_directory_profile_grants_no_home_or_network() {
        let layers = base_layers("ai-agent").unwrap();
        let resolved =
            crate::config::resolve_with_bases(&layers, std::path::Path::new("/bin/true"), None)
                .unwrap();
        let home = std::env::var("HOME").unwrap();
        assert!(
            !resolved
                .policy
                .filesystem
                .iter()
                .any(|rule| rule.path.starts_with(&home)),
            "the profile must not reach the home directory"
        );
        assert_eq!(
            resolved.policy.network.egress,
            crate::policy::Egress::DenyAll
        );
        assert!(resolved.policy.devices.iter().all(|rule| {
            // The untrusted floor's terminal and null devices are the only ones.
            rule.path.starts_with("/dev/null")
                || rule.path.starts_with("/dev/zero")
                || rule.path.starts_with("/dev/full")
                || rule.path.starts_with("/dev/urandom")
                || rule.path.starts_with("/dev/random")
                || rule.path.starts_with("/dev/tty")
        }));
    }
}
