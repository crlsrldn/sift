//! Parsing Xcode DeviceSupport directory names.
//!
//! These look like:
//!
//! ```text
//! 16.4 (20E247)
//! 15.0
//! 18.1.1 (22B83)
//! 17.2 (21C62) arm64e
//! ```
//!
//! S3's eligibility rule is "at least two major versions below the highest
//! present", so this needs a comparable version, not just a string. Getting it
//! wrong in the permissive direction would delete the device support bundle for
//! the phone the user is actively debugging.

use std::cmp::Ordering;

/// An OS version parsed from a DeviceSupport directory name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// Build identifier, e.g. `20E247`. Not used for ordering — builds do not
    /// sort meaningfully across major versions.
    pub build: Option<String>,
}

impl OsVersion {
    /// Parse a DeviceSupport directory name.
    ///
    /// Returns `None` rather than guessing on anything unrecognised
    /// (Principle 7: refuse rather than guess). An unparseable directory is
    /// simply never a candidate.
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim();
        if name.is_empty() {
            return None;
        }

        // Split off a parenthesised build if present.
        let (version_part, build) = match name.find('(') {
            Some(i) => {
                let rest = &name[i + 1..];
                let close = rest.find(')')?;
                let build = rest[..close].trim().to_string();
                if build.is_empty() {
                    return None;
                }
                (&name[..i], Some(build))
            }
            None => (name, None),
        };

        // Anything after the build (e.g. " arm64e") is ignored; it is an
        // architecture note, not part of the version.
        let version_part = version_part.trim();
        if version_part.is_empty() {
            return None;
        }

        let mut nums = version_part.split('.');
        let major = parse_component(nums.next()?)?;
        let minor = nums.next().map(parse_component).unwrap_or(Some(0))?;
        let patch = nums.next().map(parse_component).unwrap_or(Some(0))?;

        // A fourth component means this is not a version string we understand.
        if nums.next().is_some() {
            return None;
        }

        Some(Self {
            major,
            minor,
            patch,
            build,
        })
    }
}

fn parse_component(s: &str) -> Option<u32> {
    let s = s.trim();
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

impl Ord for OsVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}

impl PartialOrd for OsVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for OsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.patch > 0 {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        } else {
            write!(f, "{}.{}", self.major, self.minor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_common_forms() {
        let v = OsVersion::parse("16.4 (20E247)").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (16, 4, 0));
        assert_eq!(v.build.as_deref(), Some("20E247"));

        let v = OsVersion::parse("15.0").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (15, 0, 0));
        assert_eq!(v.build, None);

        let v = OsVersion::parse("18.1.1 (22B83)").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (18, 1, 1));
    }

    #[test]
    fn ignores_an_architecture_suffix() {
        let v = OsVersion::parse("17.2 (21C62) arm64e").unwrap();
        assert_eq!((v.major, v.minor), (17, 2));
        assert_eq!(v.build.as_deref(), Some("21C62"));
    }

    #[test]
    fn refuses_rather_than_guesses_on_garbage() {
        // Principle 7. An unparseable directory must never become a candidate:
        // the cost of a wrong guess here is deleting the device support for the
        // phone the user is currently debugging.
        for bad in [
            "",
            "   ",
            "not-a-version",
            "16.x",
            "(20E247)",
            "16.4 (",
            "16.4 ()",
            "1.2.3.4",
            "-1.0",
            "16..4",
            "Symbols",
            ".DS_Store",
        ] {
            assert!(
                OsVersion::parse(bad).is_none(),
                "`{bad}` should not parse as a version"
            );
        }
    }

    #[test]
    fn orders_by_numeric_components_not_lexically() {
        // "9.0" > "10.0" lexically, which would make sift delete the newest
        // bundle on any machine with a single-digit version present.
        let v9 = OsVersion::parse("9.0").unwrap();
        let v10 = OsVersion::parse("10.0").unwrap();
        assert!(v9 < v10);

        let a = OsVersion::parse("16.4").unwrap();
        let b = OsVersion::parse("16.10").unwrap();
        assert!(a < b);
    }

    #[test]
    fn build_does_not_affect_ordering() {
        let a = OsVersion::parse("16.4 (20E247)").unwrap();
        let b = OsVersion::parse("16.4 (20E999)").unwrap();
        assert_eq!(a.cmp(&b), Ordering::Equal);
    }

    #[test]
    fn displays_in_a_user_facing_form() {
        // Principle 6: reports say "iOS 16.4", not the directory name.
        assert_eq!(
            OsVersion::parse("16.4 (20E247)").unwrap().to_string(),
            "16.4"
        );
        assert_eq!(OsVersion::parse("18.1.1").unwrap().to_string(), "18.1.1");
    }

    #[test]
    fn a_realistic_directory_listing_sorts_correctly() {
        let mut versions: Vec<OsVersion> = [
            "15.0",
            "16.4 (20E247)",
            "9.3.5 (13G36)",
            "18.1 (22B83)",
            "17.2 (21C62)",
        ]
        .iter()
        .filter_map(|s| OsVersion::parse(s))
        .collect();
        versions.sort();

        let majors: Vec<u32> = versions.iter().map(|v| v.major).collect();
        assert_eq!(majors, vec![9, 15, 16, 17, 18]);
    }
}
