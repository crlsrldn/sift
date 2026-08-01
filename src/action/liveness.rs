//! Liveness guard (FR-17, spec §7.5).
//!
//! Reject any candidate whose tree contains a file modified within
//! `safety.active_window_minutes` (default 60).
//!
//! # Why the whole tree, not the directory
//!
//! A directory's own mtime changes when an entry is added or removed, not when
//! a file three levels down is rewritten. An `xcodebuild` or `cargo build` in
//! progress rewrites object files deep inside a tree whose top-level mtime can
//! be hours old. Trusting the directory mtime would let sift quarantine a
//! running build — the PRD's first listed High-severity risk.
//!
//! # Scope, honestly
//!
//! This is the v1 implementation spec §7.5 specifies, and it is a heuristic.
//! It catches the common case: a build that is actively writing. It does **not**
//! catch a process holding a file open without writing, or one about to start.
//! The `lsof`-based open-descriptor check is deferred to v2 — it is slow and
//! needs elevated privileges to see other users' processes. The quarantine
//! window (G6) is what covers the residual risk, not this check.

use crate::scan::{Candidate, ScanCtx, Target};
use chrono::{DateTime, Local};

/// Minutes since the most recent write anywhere in the candidate's tree, if
/// that is inside the active window. `None` means the candidate is quiet.
pub fn check(ctx: &ScanCtx, c: &Candidate) -> Option<i64> {
    let Target::Path(path) = &c.target else {
        // Delegated commands and snapshots have no tree to inspect. Their own
        // tools own the liveness question — `docker prune` will not remove a
        // running container's image.
        return None;
    };

    let window = chrono::Duration::minutes(ctx.config.safety.active_window_minutes as i64);
    let newest = newest_write(ctx, path)?;
    let elapsed = ctx.now - newest;

    if elapsed < window {
        Some(elapsed.num_minutes().max(0))
    } else {
        None
    }
}

/// Newest mtime anywhere under `path`, including `path` itself.
fn newest_write(ctx: &ScanCtx, path: &std::path::Path) -> Option<DateTime<Local>> {
    let own = std::fs::symlink_metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(DateTime::<Local>::from);

    let within = ctx
        .walker()
        .newest_mtime(path)
        .ok()
        .flatten()
        .map(DateTime::<Local>::from);

    match (own, within) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Capabilities;
    use crate::config::Config;
    use crate::risk::Risk;
    use chrono::Duration;
    use std::sync::Arc;

    fn ctx(cfg: Config) -> ScanCtx {
        ScanCtx::new(
            Arc::new(cfg),
            crate::fs::volume::root().unwrap(),
            Capabilities::probe(),
        )
        .unwrap()
    }

    fn candidate_at(path: &std::path::Path) -> Candidate {
        Candidate {
            scanner: "logs",
            target: Target::Path(path.to_path_buf()),
            bytes_on_disk: 1000,
            bytes_apparent: 1000,
            last_modified: Local::now() - Duration::days(90),
            risk: Risk::Safe,
            label: "x".into(),
            reason: "x".into(),
        }
    }

    #[test]
    fn a_just_written_file_deep_in_the_tree_marks_it_active() {
        // The failure this exists to prevent: a build directory whose top-level
        // mtime is hours old while xcodebuild rewrites objects three levels down.
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("Build/Intermediates/x.o");
        std::fs::create_dir_all(deep.parent().unwrap()).unwrap();
        std::fs::write(&deep, b"just written").unwrap();

        let c = ctx(Config::default());
        let result = check(&c, &candidate_at(dir.path()));
        assert!(result.is_some(), "a fresh write must mark the tree active");
    }

    #[test]
    fn a_quiet_tree_is_not_active() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("old.log");
        std::fs::write(&f, b"x").unwrap();

        let old = Local::now() - Duration::days(30);
        let ft = filetime::FileTime::from_unix_time(old.timestamp(), 0);
        filetime::set_file_mtime(&f, ft).unwrap();
        filetime::set_file_mtime(dir.path(), ft).unwrap();

        let c = ctx(Config::default());
        assert_eq!(check(&c, &candidate_at(dir.path())), None);
    }

    #[test]
    fn the_window_is_configurable() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, b"x").unwrap();

        let thirty_min_ago = Local::now() - Duration::minutes(30);
        let ft = filetime::FileTime::from_unix_time(thirty_min_ago.timestamp(), 0);
        filetime::set_file_mtime(&f, ft).unwrap();
        filetime::set_file_mtime(dir.path(), ft).unwrap();

        // Default 60-minute window: 30 minutes ago is inside it.
        let c = ctx(Config::default());
        assert!(check(&c, &candidate_at(dir.path())).is_some());

        // A 10-minute window: 30 minutes ago is outside it.
        let c = ctx(Config::parse("[safety]\nactive_window_minutes = 10\n").unwrap());
        assert_eq!(check(&c, &candidate_at(dir.path())), None);
    }

    #[test]
    fn delegated_targets_are_never_marked_active() {
        // A `brew cleanup` invocation has no tree; its own tool owns the
        // liveness question.
        let mut c = candidate_at(std::path::Path::new("/tmp"));
        c.target = Target::Delegated(crate::scan::DelegatedCmd::new("brew", &["cleanup"]));
        assert_eq!(check(&ctx(Config::default()), &c), None);
    }

    #[test]
    fn a_vanished_path_is_treated_as_quiet() {
        // Nothing to protect, and the later rename will fail harmlessly.
        let c = candidate_at(std::path::Path::new("/no/such/path/here"));
        assert_eq!(check(&ctx(Config::default()), &c), None);
    }
}
