//! Machine-readable output (FR-10).
//!
//! Stability contract: `schema_version` is bumped on any breaking change to the
//! shape. Callers pin it. Adding a field is not breaking; removing or retyping
//! one is.
//!
//! Under `--json`, stdout carries **only** this document. All logging goes to
//! stderr (see `logging`), so `sift scan --json | jq` works regardless of
//! `SIFT_LOG`.

use crate::scan::{ScanCtx, ScanReport};

pub const SCHEMA_VERSION: u32 = 1;

pub fn scan_report(report: &ScanReport, ctx: &ScanCtx) -> serde_json::Value {
    serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "duration_ms": report.duration.as_millis() as u64,
        "volume": {
            "name": ctx.root_volume.name,
            "fs_type": ctx.root_volume.fs_type,
            "total_bytes": ctx.root_volume.total,
            // Both figures, per spec §5.1. A consumer comparing against `df`
            // needs the raw one to understand why the numbers differ.
            "available_important_bytes": ctx.root_volume.available_important,
            "available_raw_bytes": ctx.root_volume.available_raw,
            "purgeable_bytes": ctx.root_volume.purgeable(),
        },
        "total_bytes": report.total_bytes(),
        "bytes_by_scanner": report.bytes_by_scanner(),
        "candidates": report.candidates.iter().map(|c| serde_json::json!({
            "scanner": c.scanner,
            "target": c.target.display(),
            // FR-15: whether quarantine can undo this. Delegated commands
            // cannot, and a consumer deciding whether to auto-approve needs
            // that distinction more than it needs the byte count.
            "reversible": c.target.is_reversible(),
            "bytes_on_disk": c.bytes_on_disk,
            "bytes_apparent": c.bytes_apparent,
            // spec §5.3: block accounting overcounts APFS clones. Saying so in
            // the machine format too keeps a consumer from treating this as
            // exact.
            "bytes_are_estimate": true,
            "risk": c.risk.as_str(),
            "label": c.label,
            "reason": c.reason,
            "last_modified": c.last_modified.to_rfc3339(),
            "age_days": c.age_days(ctx.now),
        })).collect::<Vec<_>>(),
        // Kept out of `candidates` and out of `total_bytes` on purpose: an
        // automated consumer that acted on this list would be acting on
        // scanners the user switched off. Present only under
        // --include-disabled, and always empty otherwise.
        "disabled_total_bytes": report.disabled_bytes(),
        "disabled_candidates": report.disabled_candidates.iter().map(|c| serde_json::json!({
            "scanner": c.scanner,
            "target": c.target.display(),
            "reversible": c.target.is_reversible(),
            "bytes_on_disk": c.bytes_on_disk,
            "bytes_apparent": c.bytes_apparent,
            "bytes_are_estimate": true,
            "risk": c.risk.as_str(),
            "label": c.label,
            "reason": c.reason,
            "last_modified": c.last_modified.to_rfc3339(),
            "age_days": c.age_days(ctx.now),
            "actionable": false,
        })).collect::<Vec<_>>(),
        "skipped": report.skipped.iter().map(|(id, why)| serde_json::json!({
            "scanner": id,
            "reason": why.describe(),
            "blocked": matches!(why,
                crate::scan::SkippedScanner::NeedsFda
                | crate::scan::SkippedScanner::NeedsTool(_)),
        })).collect::<Vec<_>>(),
        "errors": report.errors.iter().map(|(id, msg)| serde_json::json!({
            "scanner": id,
            "error": msg,
        })).collect::<Vec<_>>(),
        "deleted_anything": false,
    })
}
