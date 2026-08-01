//! Built-in defaults (FR-22).
//!
//! Absence of a config file means "all defaults", and the defaults are
//! conservative: **every Destructive scanner is off.** That property is asserted
//! by a test rather than left to inspection.

use crate::config::bytesize::ByteSize;
use crate::risk::Risk;

// ---------------------------------------------------------------------------
// General
// ---------------------------------------------------------------------------

pub const MAX_RISK: Risk = Risk::Rebuildable;
pub const MAX_BYTES_PER_RUN: ByteSize = ByteSize::gib(100);
pub const QUARANTINE_TTL_DAYS: u32 = 7;
pub const FREE_SPACE_FLOOR: ByteSize = ByteSize::gib(100);

// ---------------------------------------------------------------------------
// Safety
// ---------------------------------------------------------------------------

/// FR-17 liveness guard: reject any candidate whose tree contains a file
/// modified within this window.
pub const ACTIVE_WINDOW_MINUTES: u32 = 60;

/// Depth cap for the walker, as a cycle backstop (spec §5.2).
pub const MAX_WALK_DEPTH: usize = 24;

// ---------------------------------------------------------------------------
// Schedule
// ---------------------------------------------------------------------------

pub const SCHEDULE_HOUR: u32 = 3;
pub const SCHEDULE_MINUTE: u32 = 0;
pub const SKIP_ON_BATTERY_BELOW: u8 = 30;
pub const NOTIFY_THRESHOLD: ByteSize = ByteSize::gib(1);

/// Resolution of PRD Open Question 2.
///
/// The free-space floor means a comfortable disk is left alone, which is
/// elegant but means the first run after a long quiet period is the biggest and
/// riskiest. This overrides the floor once a run has not happened in this many
/// days, so work stays incremental.
pub const MAX_DAYS_BETWEEN_RUNS: u32 = 14;

// ---------------------------------------------------------------------------
// Scanners
// ---------------------------------------------------------------------------

/// Per-scanner defaults, from the PRD §6.1 table.
pub struct ScannerDefault {
    pub id: &'static str,
    /// `None` for delegated scanners where age is not the eligibility criterion.
    pub min_age_days: Option<u32>,
    pub risk: Risk,
    pub enabled: bool,
    /// Scanner-specific config keys this scanner accepts, beyond the common set.
    pub extra_keys: &'static [&'static str],
    /// Whether this scanner needs Full Disk Access (spec §10 permissions matrix).
    pub requires_fda: bool,
    /// External tool without which this scanner cannot run at all. Absence
    /// means "skip with a reason", never an error (FR-4, FR-27).
    pub requires_tool: Option<&'static str>,
    /// Tools that improve this scanner but are not required — sift delegates to
    /// them when present and falls back to a native implementation otherwise.
    pub optional_tools: &'static [&'static str],
}

/// The full scanner registry as far as *configuration* is concerned.
///
/// The executable registry arrives in PR-09; a test there asserts these two
/// lists agree, so a scanner cannot exist without config defaults or vice versa.
pub const SCANNERS: &[ScannerDefault] = &[
    ScannerDefault {
        id: "snapshots", // S1
        min_age_days: Some(7),
        risk: Risk::Destructive,
        enabled: false,
        requires_fda: true,
        requires_tool: Some("tmutil"),
        optional_tools: &[],
        extra_keys: &["urgency"],
    },
    ScannerDefault {
        id: "xcode-derived", // S2
        min_age_days: Some(14),
        risk: Risk::Rebuildable,
        enabled: true,
        requires_fda: false,
        requires_tool: None,
        optional_tools: &[],
        extra_keys: &[],
    },
    ScannerDefault {
        id: "xcode-devicesupport", // S3
        min_age_days: Some(90),
        risk: Risk::Rebuildable,
        enabled: true,
        requires_fda: false,
        requires_tool: None,
        optional_tools: &[],
        extra_keys: &[],
    },
    ScannerDefault {
        id: "xcode-archives", // S4
        min_age_days: Some(180),
        risk: Risk::Destructive,
        enabled: false,
        requires_fda: false,
        requires_tool: None,
        optional_tools: &[],
        extra_keys: &[],
    },
    ScannerDefault {
        id: "simulators", // S5
        min_age_days: None,
        risk: Risk::Rebuildable,
        enabled: true,
        requires_fda: false,
        requires_tool: Some("xcrun"),
        optional_tools: &[],
        extra_keys: &[],
    },
    ScannerDefault {
        id: "rust-targets", // S6
        min_age_days: Some(30),
        risk: Risk::Rebuildable,
        enabled: true,
        requires_fda: false,
        requires_tool: None,
        optional_tools: &["cargo-sweep"],
        extra_keys: &["prefer_delegation"],
    },
    ScannerDefault {
        id: "cargo-cache", // S7
        min_age_days: Some(60),
        risk: Risk::Safe,
        enabled: true,
        requires_fda: false,
        requires_tool: None,
        optional_tools: &["cargo-cache"],
        extra_keys: &["prefer_delegation"],
    },
    ScannerDefault {
        id: "homebrew", // S8
        min_age_days: None,
        risk: Risk::Safe,
        enabled: true,
        requires_fda: false,
        requires_tool: Some("brew"),
        optional_tools: &[],
        extra_keys: &["autoremove"],
    },
    ScannerDefault {
        id: "containers", // S9
        min_age_days: None,
        risk: Risk::Rebuildable,
        enabled: true,
        requires_fda: false,
        requires_tool: Some("docker"),
        optional_tools: &[],
        extra_keys: &[],
    },
    ScannerDefault {
        id: "node-caches", // S10
        min_age_days: Some(60),
        risk: Risk::Safe,
        enabled: true,
        requires_fda: false,
        requires_tool: None,
        optional_tools: &["pnpm", "yarn", "npm"],
        extra_keys: &[],
    },
    ScannerDefault {
        id: "python-caches", // S11
        min_age_days: Some(60),
        risk: Risk::Safe,
        enabled: true,
        requires_fda: false,
        requires_tool: None,
        optional_tools: &["uv"],
        extra_keys: &[],
    },
    ScannerDefault {
        id: "trash", // S12
        min_age_days: Some(30),
        risk: Risk::Destructive,
        enabled: false,
        requires_fda: true,
        requires_tool: None,
        optional_tools: &[],
        extra_keys: &[],
    },
    ScannerDefault {
        id: "downloads", // S13
        min_age_days: Some(90),
        risk: Risk::Destructive,
        enabled: false,
        requires_fda: false,
        requires_tool: None,
        optional_tools: &[],
        extra_keys: &[],
    },
    ScannerDefault {
        id: "app-caches", // S14
        min_age_days: Some(30),
        risk: Risk::Safe,
        enabled: true,
        requires_fda: false,
        requires_tool: None,
        optional_tools: &[],
        extra_keys: &[],
    },
    ScannerDefault {
        id: "ios-backups", // S15
        min_age_days: Some(365),
        risk: Risk::Destructive,
        enabled: false,
        requires_fda: true,
        requires_tool: None,
        optional_tools: &[],
        extra_keys: &[],
    },
    ScannerDefault {
        id: "mail-downloads", // S16
        min_age_days: Some(90),
        risk: Risk::Safe,
        enabled: true,
        requires_fda: true,
        requires_tool: None,
        optional_tools: &[],
        extra_keys: &[],
    },
    ScannerDefault {
        id: "logs", // S17
        min_age_days: Some(30),
        risk: Risk::Safe,
        enabled: true,
        requires_fda: false,
        requires_tool: None,
        optional_tools: &[],
        extra_keys: &[],
    },
];

pub fn scanner(id: &str) -> Option<&'static ScannerDefault> {
    SCANNERS.iter().find(|s| s.id == id)
}

pub fn scanner_ids() -> Vec<&'static str> {
    SCANNERS.iter().map(|s| s.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_destructive_scanner_is_off_by_default() {
        // FR-22. This is the single most important assertion in this file: it is
        // what makes "install it and forget it" safe on an unconfigured machine.
        for s in SCANNERS {
            if s.risk == Risk::Destructive {
                assert!(
                    !s.enabled,
                    "destructive scanner `{}` is enabled by default",
                    s.id
                );
            }
        }
    }

    #[test]
    fn the_prd_destructive_set_is_exactly_what_we_expect() {
        // Guards against a scanner silently changing tier. PRD §6.1: S1, S4,
        // S12, S13, S15.
        let destructive: HashSet<&str> = SCANNERS
            .iter()
            .filter(|s| s.risk == Risk::Destructive)
            .map(|s| s.id)
            .collect();

        let expected: HashSet<&str> = [
            "snapshots",
            "xcode-archives",
            "trash",
            "downloads",
            "ios-backups",
        ]
        .into_iter()
        .collect();

        assert_eq!(destructive, expected);
    }

    #[test]
    fn all_seventeen_prd_scanners_are_present() {
        assert_eq!(SCANNERS.len(), 17, "PRD §6.1 defines S1..S17");
    }

    #[test]
    fn scanner_ids_are_unique() {
        let ids: HashSet<&str> = scanner_ids().into_iter().collect();
        assert_eq!(ids.len(), SCANNERS.len(), "duplicate scanner id");
    }

    #[test]
    fn default_max_risk_excludes_destructive() {
        // Even if a destructive scanner were enabled, the default max_risk must
        // not admit its candidates. Two independent switches (PR-36).
        assert!(Risk::Destructive > MAX_RISK);
    }

    #[test]
    fn min_age_matches_the_prd_table() {
        assert_eq!(scanner("xcode-derived").unwrap().min_age_days, Some(14));
        assert_eq!(
            scanner("xcode-devicesupport").unwrap().min_age_days,
            Some(90)
        );
        assert_eq!(scanner("rust-targets").unwrap().min_age_days, Some(30));
        assert_eq!(scanner("ios-backups").unwrap().min_age_days, Some(365));
        assert_eq!(scanner("simulators").unwrap().min_age_days, None);
    }
}
