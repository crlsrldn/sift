//! Size accounting against ground truth (FR-6, spec §5.3).
//!
//! The unit tests in `fs::size` check internal consistency. These check the
//! numbers against `du`, which is the only external authority available — if
//! `sift` and `du` disagree about a tree with no clones and no dataless files,
//! one of them is wrong.

use sift::fs::size::measure;
use std::fs;
use std::path::Path;

/// `du -sk` in 512-byte-block terms, matching what `st_blocks` counts.
///
/// `du -sk` reports kilobytes; `-A` is not portable here, so kilobytes are
/// converted rather than asking for blocks directly.
fn du_bytes(path: &Path) -> u64 {
    let out = std::process::Command::new("du")
        .args(["-sk"])
        .arg(path)
        .output()
        .expect("du should be available");
    let text = String::from_utf8_lossy(&out.stdout);
    let kb: u64 = text
        .split_whitespace()
        .next()
        .expect("du output should start with a number")
        .parse()
        .expect("du should report an integer");
    kb * 1024
}

/// `du` includes directory inodes; `sift` counts files only. On APFS a
/// directory occupies zero blocks, but this keeps the comparison honest about
/// what is being compared.
fn assert_close(sift_bytes: u64, du_bytes: u64, tolerance: f64, what: &str) {
    let diff = sift_bytes.abs_diff(du_bytes) as f64;
    let allowed = (du_bytes as f64 * tolerance).max(8192.0);
    assert!(
        diff <= allowed,
        "{what}: sift={sift_bytes} du={du_bytes} differ by {diff} bytes \
         (allowed {allowed})"
    );
}

#[test]
fn agrees_with_du_on_a_plain_tree() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("a/b")).unwrap();
    for (p, size) in [
        ("f1.bin", 100_000usize),
        ("a/f2.bin", 250_000),
        ("a/b/f3.bin", 1_000_000),
        ("a/b/f4.bin", 37),
    ] {
        fs::write(dir.path().join(p), vec![0xABu8; size]).unwrap();
    }

    let m = measure(dir.path()).unwrap();
    assert_close(m.bytes_on_disk, du_bytes(dir.path()), 0.02, "plain tree");
}

#[test]
fn agrees_with_du_on_a_tree_containing_hard_links() {
    // du also dedups by inode, so this is the real cross-check for FR-6: if
    // sift double-counted links, it would diverge here and only here.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("original.bin");
    fs::write(&target, vec![0x5Au8; 512_000]).unwrap();
    for i in 0..10 {
        fs::hard_link(&target, dir.path().join(format!("link{i}.bin"))).unwrap();
    }

    let m = measure(dir.path()).unwrap();
    assert_eq!(m.files, 1);
    assert_eq!(m.hardlinks_deduped, 10);
    assert_close(m.bytes_on_disk, du_bytes(dir.path()), 0.02, "hard links");
}

#[test]
fn agrees_with_du_on_a_sparse_file() {
    let dir = tempfile::tempdir().unwrap();
    let f = fs::File::create(dir.path().join("sparse.bin")).unwrap();
    f.set_len(128 * 1024 * 1024).unwrap();
    drop(f);

    let m = measure(dir.path()).unwrap();
    let du = du_bytes(dir.path());

    assert_close(m.bytes_on_disk, du, 0.10, "sparse file");
    assert!(
        m.bytes_apparent > 100 * 1024 * 1024,
        "apparent size should still reflect the declared length"
    );
}

#[test]
fn agrees_with_du_on_many_small_files() {
    // Block-rounding dominates here: 500 one-byte files occupy 500 blocks, not
    // 500 bytes. Counting st_size would report ~0.5 KB instead of ~2 MB.
    let dir = tempfile::tempdir().unwrap();
    for i in 0..500 {
        fs::write(dir.path().join(format!("f{i}")), b"x").unwrap();
    }

    let m = measure(dir.path()).unwrap();
    assert_eq!(m.files, 500);
    assert!(
        m.bytes_on_disk > m.bytes_apparent,
        "block rounding should make on-disk exceed apparent for tiny files"
    );
    assert_close(
        m.bytes_on_disk,
        du_bytes(dir.path()),
        0.05,
        "many small files",
    );
}

#[test]
fn a_deep_tree_within_the_depth_cap_agrees_with_du() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = dir.path().to_path_buf();
    for i in 0..15 {
        p = p.join(format!("d{i}"));
        fs::create_dir(&p).unwrap();
        fs::write(p.join("f.bin"), vec![0u8; 20_000]).unwrap();
    }

    let m = measure(dir.path()).unwrap();
    assert_eq!(m.files, 15);
    assert_close(m.bytes_on_disk, du_bytes(dir.path()), 0.05, "deep tree");
}

#[test]
fn measurement_never_reports_more_than_the_volume_holds() {
    // A trivial sanity bound, but it would have caught a units bug — counting
    // st_blocks as bytes-per-block rather than 512-byte units inflates every
    // figure by the filesystem block size.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("f.bin"), vec![0u8; 1_000_000]).unwrap();

    let m = measure(dir.path()).unwrap();
    let vol = sift::fs::volume::root().unwrap();
    assert!(
        m.bytes_on_disk < vol.total,
        "measured {} bytes on a {} byte volume",
        m.bytes_on_disk,
        vol.total
    );
    assert!(
        m.bytes_on_disk < 4 * 1_000_000,
        "1 MB file measured as {}",
        m.bytes_on_disk
    );
}
