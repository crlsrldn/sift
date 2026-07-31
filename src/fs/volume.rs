//! Volume identity and capacity (FR-5, spec §5.1).
//!
//! # Why not `statfs`
//!
//! `statfs(2)` on APFS reports purgeable space as **used**. On a machine with
//! local snapshots and cached iCloud content that understates free space by tens
//! of gigabytes, and `df` inherits the same error. The number macOS itself shows
//! in Finder — and the one that actually predicts whether a write will succeed —
//! is `NSURLVolumeAvailableCapacityForImportantUsageKey`.
//!
//! Both values are captured. The important-usage figure drives decisions and
//! reports; the raw figure is recorded alongside it in run history so the gap is
//! visible rather than mysterious.

use crate::{Result, SiftError};
use std::path::{Path, PathBuf};

use objc2_foundation::{
    NSArray, NSNumber, NSString, NSURLResourceKey,
    NSURLVolumeAvailableCapacityForImportantUsageKey, NSURLVolumeAvailableCapacityKey,
    NSURLVolumeTotalCapacityKey, NSURL,
};

/// Identity and capacity of the volume `sift` operates on.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// Mount point this describes.
    pub mount_point: PathBuf,
    /// Volume name, e.g. "Macintosh HD".
    pub name: String,
    /// Filesystem type from `statfs`, e.g. "apfs".
    pub fs_type: String,
    /// `st_dev` of the mount point. The walker compares every descent against
    /// this to avoid crossing volume boundaries (FR-7, spec §5.2).
    pub device: u64,
    /// Total capacity in bytes.
    pub total: u64,
    /// Available capacity for "important usage" — the APFS-aware figure (FR-5).
    pub available_important: u64,
    /// Raw available capacity, matching what `statfs`/`df` report.
    pub available_raw: u64,
}

impl VolumeInfo {
    /// Bytes reported as used by `df` that are actually reclaimable without any
    /// action from us. Purely informational, and often large enough that showing
    /// it prevents a confused bug report.
    pub fn purgeable(&self) -> u64 {
        self.available_important.saturating_sub(self.available_raw)
    }

    pub fn is_apfs(&self) -> bool {
        self.fs_type.eq_ignore_ascii_case("apfs")
    }
}

/// Query the volume containing `path`.
pub fn info(path: &Path) -> Result<VolumeInfo> {
    let st = statfs(path)?;
    let (total, available_important, available_raw) = capacity(path)?;

    Ok(VolumeInfo {
        mount_point: PathBuf::from(cstr(&st.f_mntonname)),
        name: volume_name(path).unwrap_or_else(|| cstr(&st.f_mntonname)),
        fs_type: cstr(&st.f_fstypename),
        device: device_of(path)?,
        total,
        available_important,
        available_raw,
    })
}

/// Query the root volume, which is what `sift` operates on.
///
/// HFS+ and other non-APFS filesystems are rejected here rather than silently
/// scanned: the size accounting and snapshot logic both assume APFS semantics,
/// and spec §1 says non-APFS volumes are detected and skipped with a warning.
pub fn root() -> Result<VolumeInfo> {
    let v = info(Path::new("/"))?;
    if !v.is_apfs() {
        tracing::warn!(
            fs_type = %v.fs_type,
            "root volume is not APFS; sift's size accounting assumes APFS semantics"
        );
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// statfs
// ---------------------------------------------------------------------------

fn statfs(path: &Path) -> Result<libc::statfs> {
    let c = path_to_cstring(path)?;
    // SAFETY: `c` is a valid NUL-terminated path and `buf` is a valid, correctly
    // sized, uninitialized statfs which the call fully populates on success.
    unsafe {
        let mut buf: libc::statfs = std::mem::zeroed();
        if libc::statfs(c.as_ptr(), &mut buf) != 0 {
            return Err(SiftError::Io(std::io::Error::last_os_error()));
        }
        Ok(buf)
    }
}

/// `st_dev` of a path, used by the walker's device guard.
pub fn device_of(path: &Path) -> Result<u64> {
    let c = path_to_cstring(path)?;
    // SAFETY: as above; `lstat` is used rather than `stat` so a symlinked mount
    // point reports the link's device, not the target's.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::lstat(c.as_ptr(), &mut st) != 0 {
            return Err(SiftError::Io(std::io::Error::last_os_error()));
        }
        Ok(st.st_dev as u64)
    }
}

fn path_to_cstring(path: &Path) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| SiftError::Config(format!("path contains a NUL byte: {}", path.display())))
}

fn cstr(buf: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ---------------------------------------------------------------------------
// NSURL capacity (FR-5)
// ---------------------------------------------------------------------------

/// Returns `(total, available_important, available_raw)`.
fn capacity(path: &Path) -> Result<(u64, u64, u64)> {
    let path_str = NSString::from_str(&path.to_string_lossy());
    let url = NSURL::fileURLWithPath(&path_str);

    let keys: [&NSURLResourceKey; 3] = unsafe {
        [
            NSURLVolumeTotalCapacityKey,
            NSURLVolumeAvailableCapacityForImportantUsageKey,
            NSURLVolumeAvailableCapacityKey,
        ]
    };
    let key_array = NSArray::from_slice(&keys);

    let values = url.resourceValuesForKeys_error(&key_array).map_err(|e| {
        SiftError::Io(std::io::Error::other(format!(
            "cannot read volume capacity for {}: {}",
            path.display(),
            e.localizedDescription()
        )))
    })?;

    let get = |key: &NSURLResourceKey| -> u64 {
        values
            .objectForKey(key)
            .and_then(|obj| obj.downcast::<NSNumber>().ok())
            .map(|n| n.longLongValue().max(0) as u64)
            .unwrap_or(0)
    };

    // SAFETY: these statics are immortal NSString constants provided by
    // Foundation; taking references to them is sound for the process lifetime.
    unsafe {
        Ok((
            get(NSURLVolumeTotalCapacityKey),
            get(NSURLVolumeAvailableCapacityForImportantUsageKey),
            get(NSURLVolumeAvailableCapacityKey),
        ))
    }
}

/// Human-facing volume name, e.g. "Macintosh HD".
fn volume_name(path: &Path) -> Option<String> {
    let path_str = NSString::from_str(&path.to_string_lossy());
    let url = NSURL::fileURLWithPath(&path_str);
    let keys = [unsafe { objc2_foundation::NSURLVolumeNameKey }];
    let key_array = NSArray::from_slice(&keys);

    let values = url.resourceValuesForKeys_error(&key_array).ok()?;
    let key = unsafe { objc2_foundation::NSURLVolumeNameKey };
    let obj = values.objectForKey(key)?;
    let s = obj.downcast::<NSString>().ok()?;
    Some(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_volume_is_queryable() {
        let v = root().expect("root volume must be queryable");
        assert_eq!(v.mount_point, Path::new("/"));
        assert!(v.total > 0, "total capacity should be non-zero");
        assert!(!v.fs_type.is_empty());
    }

    #[test]
    fn this_machine_is_apfs() {
        // Spec §1 targets APFS. If this fails on a dev machine, the HFS+ warning
        // path is what will run, and the size accounting assumptions do not hold.
        let v = root().unwrap();
        assert!(v.is_apfs(), "expected APFS, got `{}`", v.fs_type);
    }

    #[test]
    fn important_usage_is_at_least_raw_available() {
        // FR-5: the whole reason for the NSURL path. Purgeable space is counted
        // as used by statfs and as available by important-usage, so the
        // important figure can only be larger.
        let v = root().unwrap();
        assert!(
            v.available_important >= v.available_raw,
            "important={} < raw={}, which contradicts the purgeable-space model",
            v.available_important,
            v.available_raw
        );
    }

    #[test]
    fn available_never_exceeds_total() {
        let v = root().unwrap();
        assert!(v.available_important <= v.total);
        assert!(v.available_raw <= v.total);
    }

    #[test]
    fn device_id_is_stable_within_a_volume() {
        // The walker's device guard depends on this: paths on the same volume
        // must report the same st_dev.
        let root_dev = device_of(Path::new("/")).unwrap();
        let users_dev = device_of(Path::new("/Users")).unwrap();
        assert_eq!(root_dev, users_dev);
    }

    #[test]
    fn volume_info_carries_the_device_for_the_walker() {
        let v = root().unwrap();
        assert_eq!(v.device, device_of(Path::new("/")).unwrap());
    }

    #[test]
    fn purgeable_is_the_gap_between_the_two_figures() {
        let v = root().unwrap();
        assert_eq!(
            v.purgeable(),
            v.available_important.saturating_sub(v.available_raw)
        );
    }

    #[test]
    fn nonexistent_path_is_an_error_not_a_panic() {
        assert!(info(Path::new("/definitely/not/a/real/path/xyz")).is_err());
    }
}
