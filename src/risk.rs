//! Risk tiers (PRD §6.1).
//!
//! Lives at the crate root rather than inside `scan/` because `config` needs it
//! for `max_risk` and must not depend on the scanner subsystem.

use serde::{Deserialize, Serialize};

/// How bad it is if we are wrong about a candidate.
///
/// The `Ord` derive is load-bearing: the action pipeline filters with
/// `candidate.risk <= config.max_risk`, so variant order defines the safety
/// ladder. `Safe` must stay first and `Destructive` last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    /// Regenerated automatically, no user-visible effect. (Caches.)
    Safe,
    /// Regenerated at a cost: time, bandwidth, or a rebuild.
    Rebuildable,
    /// Not recoverable once purged. Requires explicit per-scanner opt-in.
    Destructive,
}

impl Risk {
    pub fn as_str(self) -> &'static str {
        match self {
            Risk::Safe => "safe",
            Risk::Rebuildable => "rebuildable",
            Risk::Destructive => "destructive",
        }
    }

    /// Plain-English consequence, shown in reports (Principle 6).
    pub fn describe(self) -> &'static str {
        match self {
            Risk::Safe => "regenerates automatically",
            Risk::Rebuildable => "regenerates at a cost",
            Risk::Destructive => "not recoverable once purged",
        }
    }
}

impl std::fmt::Display for Risk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Risk {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "safe" => Ok(Risk::Safe),
            "rebuildable" => Ok(Risk::Rebuildable),
            "destructive" => Ok(Risk::Destructive),
            other => Err(format!(
                "unknown risk tier `{other}`; expected one of: safe, rebuildable, destructive"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_defines_the_safety_ladder() {
        // The action pipeline filters on `risk <= max_risk`. If this ordering
        // ever inverts, `max_risk = "safe"` would admit destructive candidates.
        assert!(Risk::Safe < Risk::Rebuildable);
        assert!(Risk::Rebuildable < Risk::Destructive);
        assert!(Risk::Safe < Risk::Destructive);
    }

    #[test]
    fn max_risk_safe_excludes_everything_above_it() {
        let max = Risk::Safe;
        assert!(Risk::Safe <= max);
        assert!(!(Risk::Rebuildable <= max));
        assert!(!(Risk::Destructive <= max));
    }

    #[test]
    fn parses_case_insensitively_and_rejects_garbage() {
        assert_eq!("safe".parse::<Risk>().unwrap(), Risk::Safe);
        assert_eq!("REBUILDABLE".parse::<Risk>().unwrap(), Risk::Rebuildable);
        assert_eq!(
            "  destructive  ".parse::<Risk>().unwrap(),
            Risk::Destructive
        );
        assert!("dangerous".parse::<Risk>().is_err());
        assert!("".parse::<Risk>().is_err());
    }

    #[test]
    fn error_message_lists_valid_values() {
        let e = "nope".parse::<Risk>().unwrap_err();
        assert!(e.contains("safe"));
        assert!(e.contains("rebuildable"));
        assert!(e.contains("destructive"));
    }
}
