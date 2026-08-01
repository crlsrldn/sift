//! Quarantine: staging deletions by rename (FR-11, FR-12, spec §7.1).
//!
//! # Why rename and not copy
//!
//! `rename(2)` within a volume is an inode operation: O(1), and it consumes
//! **zero additional bytes**. That matters more than it sounds — the user
//! running this is at 2 GB free, and a quarantine that copied would fail
//! exactly when it is needed most. It is also what makes the reversibility
//! promise (G6) affordable: undo is another rename.
//!
//! # Correction C1
//!
//! The technical spec §7 says `renameat2`. That is a Linux syscall and does not
//! exist on macOS. The equivalent is `renamex_np(2)` with `RENAME_EXCL`, which
//! fails rather than clobbering an existing destination — the atomic no-clobber
//! guarantee, without a check-then-act race.
//!
//! # The safety rails
//!
//! Every destination is verified to be under the quarantine root after
//! canonicalisation, and no source inside the quarantine root is ever accepted.
//! Both are checked immediately before the move, not merely computed correctly
//! upstream.

use crate::action::manifest::{Item, Manifest};
use crate::paths;
use crate::scan::{Candidate, Target};
use crate::{Result, SiftError};
use std::path::{Component, Path, PathBuf};

/// Outcome of quarantining one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Staged {
    /// Renamed into quarantine. Reversible.
    Renamed,
    /// Cross-volume, so moved to macOS Trash instead (FR-12). Not reversible
    /// by `sift restore`.
    Trashed,
    /// Refused, with a reason. Nothing happened.
    Refused(String),
}

/// What one `quarantine` call did.
#[derive(Debug, Default)]
pub struct Outcome {
    pub run_id: String,
    pub run_dir: PathBuf,
    pub renamed: usize,
    pub trashed: usize,
    pub refused: Vec<(PathBuf, String)>,
    pub bytes_staged: u64,
}

/// Map an absolute source path to its location inside the run directory.
///
/// The original absolute path is encoded into the quarantine subpath (spec
/// §7.1), so two `target/` directories from different projects cannot collide.
/// Using only the basename would silently overwrite one with the other, and
/// `RENAME_EXCL` would turn that into a spurious failure at best.
pub fn quarantine_subpath(original: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for component in original.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {}
            Component::Normal(part) => out.push(part),
            // A `..` surviving into the destination would let a crafted path
            // escape the quarantine root entirely, so it is refused outright.
            //
            // `CurDir` is handled in the same arm for completeness, but note
            // that `Path::components()` already normalises `.` away — it never
            // reaches here for an interior `./`, and a leading `./` is
            // semantically a no-op. The `..` case is the one that matters.
            Component::CurDir | Component::ParentDir => {
                return Err(SiftError::Config(format!(
                    "refusing to quarantine a path containing `..`: {}",
                    original.display()
                )));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(SiftError::Config(
            "refusing to quarantine the filesystem root".into(),
        ));
    }
    Ok(out)
}

/// `renamex_np(2)` with `RENAME_EXCL` — atomic, and fails rather than
/// clobbering an existing destination (correction C1).
fn rename_noclobber(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let from_c = std::ffi::CString::new(from.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("source path contains a NUL byte"))?;
    let to_c = std::ffi::CString::new(to.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("destination path contains a NUL byte"))?;

    // SAFETY: both pointers are valid NUL-terminated C strings living until the
    // call returns. RENAME_EXCL makes the call fail with EEXIST rather than
    // replacing an existing destination.
    let rc = unsafe { libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), libc::RENAME_EXCL) };

    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Whether `path` resolves to somewhere inside `root`.
///
/// Canonicalises the nearest existing ancestor, so a destination that does not
/// exist yet can still be checked. A symlinked component that points outside
/// the root is caught, because canonicalisation resolves it.
fn is_within(root: &Path, path: &Path) -> bool {
    let Ok(root) = root.canonicalize() else {
        return false;
    };

    let mut probe = path.to_path_buf();
    let mut suffix = Vec::new();
    loop {
        if let Ok(real) = probe.canonicalize() {
            let mut resolved = real;
            for part in suffix.iter().rev() {
                resolved.push(part);
            }
            return resolved.starts_with(&root);
        }
        let Some(name) = probe.file_name().map(|n| n.to_os_string()) else {
            return false;
        };
        suffix.push(name);
        if !probe.pop() {
            return false;
        }
    }
}

/// Stage a set of candidates into a fresh quarantine run.
///
/// The manifest is written **before** anything moves (see `manifest`), so a
/// crash leaves a recoverable record rather than orphaned rubble.
pub fn quarantine(candidates: &[Candidate], ttl_days: u32) -> Result<(Outcome, Manifest)> {
    let root = paths::quarantine_dir()?;
    let run_id = uuid::Uuid::now_v7().to_string();
    let run_dir = root.join(&run_id);
    std::fs::create_dir_all(&run_dir)?;

    let mut manifest = Manifest::new(run_id.clone(), ttl_days);
    let mut outcome = Outcome {
        run_id: run_id.clone(),
        run_dir: run_dir.clone(),
        ..Default::default()
    };

    // Build the intended item list first.
    let mut planned: Vec<(usize, PathBuf, PathBuf)> = Vec::new();
    for c in candidates {
        let Target::Path(src) = &c.target else {
            // Delegated and snapshot targets bypass quarantine entirely
            // (FR-15). They are handled by the delegate runner, not here.
            continue;
        };

        let sub = match quarantine_subpath(src) {
            Ok(s) => s,
            Err(e) => {
                outcome.refused.push((src.clone(), e.to_string()));
                continue;
            }
        };

        let idx = manifest.items.len();
        manifest.items.push(Item {
            original_path: src.clone(),
            quarantine_path: sub.clone(),
            bytes_on_disk: c.bytes_on_disk,
            scanner: c.scanner.to_string(),
            risk: c.risk,
            via_trash: false,
            moved: false,
        });
        planned.push((idx, src.clone(), run_dir.join(&sub)));
    }

    // Durable record of intent, before a single byte moves.
    manifest.save(&run_dir)?;

    for (idx, src, dest) in planned {
        match stage_one(&root, &src, &dest) {
            Ok(Staged::Renamed) => {
                manifest.items[idx].moved = true;
                outcome.renamed += 1;
                outcome.bytes_staged += manifest.items[idx].bytes_on_disk;
            }
            Ok(Staged::Trashed) => {
                manifest.items[idx].moved = true;
                manifest.items[idx].via_trash = true;
                outcome.trashed += 1;
                outcome.bytes_staged += manifest.items[idx].bytes_on_disk;
            }
            Ok(Staged::Refused(why)) | Err(SiftError::Config(why)) => {
                outcome.refused.push((src, why));
            }
            Err(e) => {
                outcome.refused.push((src, e.to_string()));
            }
        }
    }

    // Record what actually happened.
    manifest.save(&run_dir)?;
    Ok((outcome, manifest))
}

/// Move one path into quarantine, with every rail checked at the point of use.
fn stage_one(root: &Path, src: &Path, dest: &Path) -> Result<Staged> {
    // Rail 1: never re-quarantine something already in quarantine. Without
    // this, a bug that fed quarantine back into a scan would nest runs inside
    // each other and make restore incoherent.
    if is_within(root, src) {
        return Ok(Staged::Refused(
            "already inside the quarantine directory".into(),
        ));
    }

    // Rail 2: the destination must land under the quarantine root. Checked
    // after path construction rather than trusting it, because a symlinked
    // component would otherwise redirect the write outside.
    if !is_within(root, dest) {
        return Ok(Staged::Refused(format!(
            "destination {} would fall outside the quarantine root",
            dest.display()
        )));
    }

    if !src.exists() {
        return Ok(Staged::Refused("vanished before it could be staged".into()));
    }

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    match rename_noclobber(src, dest) {
        Ok(()) => Ok(Staged::Renamed),

        // EXDEV: different volume, so a rename is impossible. FR-12 says fall
        // back to macOS Trash and label it honestly — the user gets a familiar
        // recovery UI, but `sift restore` cannot undo it.
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => match trash::delete(src) {
            Ok(()) => Ok(Staged::Trashed),
            Err(te) => Ok(Staged::Refused(format!(
                "on another volume and could not be trashed: {te}"
            ))),
        },

        // EEXIST from RENAME_EXCL: something is already at the destination.
        // Refuse rather than clobber — that is the entire point of the flag.
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(Staged::Refused(
            "a quarantined item already occupies that path".into(),
        )),

        Err(e) => Ok(Staged::Refused(e.to_string())),
    }
}

/// Every quarantine run currently on disk, newest first.
pub fn runs() -> Result<Vec<Manifest>> {
    let root = paths::quarantine_dir()?;
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        // A run directory without a readable manifest is skipped rather than
        // failing the command: one bad run must not make `purge` or `restore`
        // unusable for every other run.
        if let Ok(m) = Manifest::load(&entry.path()) {
            out.push(m);
        }
    }
    out.sort_by_key(|m| std::cmp::Reverse(m.created_at));
    Ok(out)
}

/// Resolve a run-id prefix to exactly one run.
pub fn resolve_run(prefix: &str) -> Result<Manifest> {
    let all = runs()?;
    let matches: Vec<Manifest> = all
        .into_iter()
        .filter(|m| m.run_id.starts_with(prefix))
        .collect();

    match matches.len() {
        0 => Err(SiftError::Usage(format!(
            "no quarantine run matches `{prefix}`"
        ))),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => Err(SiftError::Usage(format!(
            "`{prefix}` matches {n} runs; use more characters"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_original_path_is_encoded_into_the_destination() {
        // spec §7.1: two `target/` directories from different projects must not
        // collide. Using only the basename would make them the same path.
        let a = quarantine_subpath(Path::new("/Users/x/dev/alpha/target")).unwrap();
        let b = quarantine_subpath(Path::new("/Users/x/dev/beta/target")).unwrap();

        assert_ne!(a, b);
        assert_eq!(a, Path::new("Users/x/dev/alpha/target"));
        assert!(a.is_relative(), "must be relative to the run directory");
    }

    #[test]
    fn a_path_containing_dotdot_is_refused() {
        // A `..` surviving into the destination would let a crafted path escape
        // the quarantine root.
        assert!(quarantine_subpath(Path::new("/Users/x/../../etc/passwd")).is_err());
        assert!(quarantine_subpath(Path::new("/a/b/..")).is_err());
        assert!(quarantine_subpath(Path::new("/../etc")).is_err());
    }

    #[test]
    fn an_interior_dot_component_is_normalised_away_not_refused() {
        // `Path::components()` drops `.` before this function sees it, and a
        // `./` is semantically a no-op anyway. Documented rather than asserted
        // as a refusal, because a test claiming otherwise would be wrong about
        // what the code does.
        let out = quarantine_subpath(Path::new("/a/./b")).unwrap();
        assert_eq!(out, Path::new("a/b"));
    }

    #[test]
    fn the_filesystem_root_is_refused() {
        assert!(quarantine_subpath(Path::new("/")).is_err());
    }

    #[test]
    fn rename_noclobber_refuses_an_occupied_destination() {
        // The RENAME_EXCL guarantee (correction C1). Without it a rename would
        // silently replace whatever was there.
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"source").unwrap();
        std::fs::write(&b, b"MUST SURVIVE").unwrap();

        let err = rename_noclobber(&a, &b).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EEXIST));

        assert_eq!(std::fs::read(&b).unwrap(), b"MUST SURVIVE");
        assert!(a.exists(), "the source must be untouched after a refusal");
    }

    #[test]
    fn rename_noclobber_succeeds_onto_a_free_path() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"payload").unwrap();

        rename_noclobber(&a, &b).unwrap();
        assert!(!a.exists());
        assert_eq!(std::fs::read(&b).unwrap(), b"payload");
    }

    #[test]
    fn containment_accepts_paths_inside_and_rejects_paths_outside() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("quarantine");
        std::fs::create_dir_all(root.join("run1")).unwrap();

        assert!(is_within(&root, &root.join("run1")));
        assert!(is_within(&root, &root.join("run1/does/not/exist/yet")));
        assert!(!is_within(&root, Path::new("/etc")));
        assert!(!is_within(&root, dir.path()));
    }

    #[test]
    fn containment_resolves_a_symlink_pointing_out_of_the_root() {
        // A symlinked component inside the quarantine tree must not be able to
        // redirect a write outside it.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("quarantine");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();

        assert!(
            !is_within(&root, &root.join("escape/payload")),
            "a symlink out of the root must not be treated as inside it"
        );
    }
}
