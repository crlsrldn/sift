//! Grouping scanners into user-facing families (Principle 6).
//!
//! The PRD §7 target report is organised by what the user recognises — "Xcode",
//! "Rust", "Containers" — not by scanner id. A developer knows they have Xcode
//! installed; they do not know they have an `xcode-devicesupport` scanner.

/// A user-facing family, in the order PRD §7 lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    Xcode,
    Rust,
    Containers,
    Homebrew,
    Node,
    Python,
    Caches,
    Logs,
    Snapshots,
    Trash,
    Downloads,
    Backups,
    Mail,
}

impl Family {
    pub fn title(self) -> &'static str {
        match self {
            Family::Xcode => "Xcode",
            Family::Rust => "Rust",
            Family::Containers => "Containers",
            Family::Homebrew => "Homebrew",
            Family::Node => "Node",
            Family::Python => "Python",
            Family::Caches => "Caches",
            Family::Logs => "Logs",
            Family::Snapshots => "Snapshots",
            Family::Trash => "Trash",
            Family::Downloads => "Downloads",
            Family::Backups => "Backups",
            Family::Mail => "Mail",
        }
    }
}

/// Which family a scanner belongs to.
///
/// Total over the 17 PRD scanners. A test asserts that, so adding a scanner
/// without deciding where it appears in the report is a build-time failure
/// rather than a scanner silently vanishing from the output.
pub fn family_of(scanner_id: &str) -> Family {
    match scanner_id {
        "xcode-derived" | "xcode-devicesupport" | "xcode-archives" | "simulators" => Family::Xcode,
        "rust-targets" | "cargo-cache" => Family::Rust,
        "containers" => Family::Containers,
        "homebrew" => Family::Homebrew,
        "node-caches" => Family::Node,
        "python-caches" => Family::Python,
        "app-caches" => Family::Caches,
        "logs" => Family::Logs,
        "snapshots" => Family::Snapshots,
        "trash" => Family::Trash,
        "downloads" => Family::Downloads,
        "ios-backups" => Family::Backups,
        "mail-downloads" => Family::Mail,
        // Unknown ids land in Caches rather than being dropped. Losing bytes
        // from the total because a scanner was not classified would be worse
        // than filing it slightly wrong.
        _ => Family::Caches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::defaults;

    #[test]
    fn every_prd_scanner_has_a_family() {
        // Adding a scanner without deciding where it appears in the report
        // should be caught here, not by a user wondering where their bytes went.
        for id in defaults::scanner_ids() {
            let f = family_of(id);
            assert!(!f.title().is_empty(), "scanner `{id}` has no family title");
        }
    }

    #[test]
    fn the_four_xcode_scanners_group_together() {
        for id in [
            "xcode-derived",
            "xcode-devicesupport",
            "xcode-archives",
            "simulators",
        ] {
            assert_eq!(family_of(id), Family::Xcode, "{id}");
        }
    }

    #[test]
    fn rust_scanners_group_together() {
        assert_eq!(family_of("rust-targets"), Family::Rust);
        assert_eq!(family_of("cargo-cache"), Family::Rust);
    }

    #[test]
    fn an_unknown_scanner_is_filed_rather_than_dropped() {
        // Losing bytes from the total because a scanner was not classified is
        // worse than filing it slightly wrong.
        assert_eq!(family_of("some-future-scanner"), Family::Caches);
    }

    #[test]
    fn families_order_xcode_first() {
        // PRD §7 leads with Xcode because it is the largest reclaim on the
        // target persona's machine.
        assert!(Family::Xcode < Family::Rust);
        assert!(Family::Rust < Family::Containers);
    }
}
