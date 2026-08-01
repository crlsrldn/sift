//! `clean` → `restore` round-trip fidelity (G6, spec §12).
//!
//! Property: for a randomly generated tree, quarantining and then restoring
//! produces a **byte-identical** result — same relative paths, same contents,
//! same file modes.
//!
//! G6 promises "every action reversible for a configurable window". A restore
//! that returns *approximately* the tree is not reversibility; it is a second,
//! subtler kind of data loss.

use proptest::prelude::*;
use sift::action::{quarantine, restore};
use sift::risk::Risk;
use sift::scan::{Candidate, Target};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Relative path → (contents, mode). Enough to detect any corruption a rename
/// could plausibly introduce.
fn fingerprint(root: &Path) -> BTreeMap<String, (Vec<u8>, u32)> {
    let mut out = BTreeMap::new();
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, (Vec<u8>, u32)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(m) = fs::symlink_metadata(&p) else {
                continue;
            };
            let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
            if m.is_dir() {
                out.insert(format!("{rel}/"), (Vec::new(), m.permissions().mode()));
                walk(base, &p, out);
            } else {
                out.insert(
                    rel,
                    (fs::read(&p).unwrap_or_default(), m.permissions().mode()),
                );
            }
        }
    }
    walk(root, root, &mut out);
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn quarantine_then_restore_is_byte_identical(
        files in prop::collection::vec(
            ("[a-z]{1,6}(/[a-z]{1,6}){0,3}", prop::collection::vec(any::<u8>(), 0..2048)),
            1..12,
        ),
    ) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("XDG_STATE_HOME");
        std::env::set_var("XDG_STATE_HOME", dir.path().join("state"));

        let tree = dir.path().join("tree");
        fs::create_dir_all(&tree).unwrap();
        for (rel, content) in &files {
            let p = tree.join(rel);
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            // A generated name may collide with an existing directory; skipping
            // is fine, the tree just has one fewer file.
            let _ = fs::write(&p, content);
        }

        let before = fingerprint(&tree);

        let candidate = Candidate {
            scanner: "logs",
            target: Target::Path(tree.clone()),
            bytes_on_disk: 1,
            bytes_apparent: 1,
            last_modified: chrono::Local::now(),
            risk: Risk::Safe,
            label: "tree".into(),
            reason: "test".into(),
        };

        let (outcome, _) = quarantine::quarantine(&[candidate], 7).unwrap();
        let staged_ok = !tree.exists();

        let restored = restore::restore(&outcome.run_id).unwrap();
        let after = fingerprint(&tree);

        match &prev {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }

        prop_assert!(staged_ok, "quarantine did not move the tree");
        prop_assert_eq!(restored.restored.len(), 1);
        prop_assert_eq!(
            before, after,
            "the restored tree is not byte-identical to the original"
        );
    }
}

#[test]
fn a_tree_with_unusual_modes_survives_the_round_trip() {
    // Permissions are part of the tree. A restore that silently normalised them
    // would break anything depending on an executable bit or a private mode.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let prev = std::env::var_os("XDG_STATE_HOME");
    std::env::set_var("XDG_STATE_HOME", dir.path().join("state"));

    let tree = dir.path().join("tree");
    fs::create_dir_all(tree.join("sub")).unwrap();
    fs::write(tree.join("script.sh"), b"#!/bin/sh\necho hi\n").unwrap();
    fs::set_permissions(tree.join("script.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(tree.join("sub/secret"), b"private").unwrap();
    fs::set_permissions(tree.join("sub/secret"), fs::Permissions::from_mode(0o600)).unwrap();

    let before = fingerprint(&tree);

    let c = Candidate {
        scanner: "logs",
        target: Target::Path(tree.clone()),
        bytes_on_disk: 1,
        bytes_apparent: 1,
        last_modified: chrono::Local::now(),
        risk: Risk::Safe,
        label: "tree".into(),
        reason: "test".into(),
    };
    let (outcome, _) = quarantine::quarantine(&[c], 7).unwrap();
    restore::restore(&outcome.run_id).unwrap();

    let after = fingerprint(&tree);

    match &prev {
        Some(v) => std::env::set_var("XDG_STATE_HOME", v),
        None => std::env::remove_var("XDG_STATE_HOME"),
    }

    assert_eq!(
        before, after,
        "modes or contents changed across the round trip"
    );
    assert_eq!(
        fs::metadata(tree.join("script.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

/// Where the restored tree ends up must be exactly where it came from.
#[test]
fn the_tree_returns_to_its_original_absolute_path() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let prev = std::env::var_os("XDG_STATE_HOME");
    std::env::set_var("XDG_STATE_HOME", dir.path().join("state"));

    let tree: PathBuf = dir.path().join("deeply/nested/original/location");
    fs::create_dir_all(&tree).unwrap();
    fs::write(tree.join("f.txt"), b"content").unwrap();

    let c = Candidate {
        scanner: "logs",
        target: Target::Path(tree.clone()),
        bytes_on_disk: 1,
        bytes_apparent: 1,
        last_modified: chrono::Local::now(),
        risk: Risk::Safe,
        label: "t".into(),
        reason: "t".into(),
    };
    let (outcome, _) = quarantine::quarantine(&[c], 7).unwrap();
    restore::restore(&outcome.run_id).unwrap();

    match &prev {
        Some(v) => std::env::set_var("XDG_STATE_HOME", v),
        None => std::env::remove_var("XDG_STATE_HOME"),
    }

    assert!(
        tree.join("f.txt").exists(),
        "not restored to the original path"
    );
    assert_eq!(fs::read(tree.join("f.txt")).unwrap(), b"content");
}
