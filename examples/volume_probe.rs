//! Prints the volume figures `sift` uses, next to what `df` would tell you.
//!
//! Kept as an example rather than a test because the interesting property — how
//! far apart the raw and important-usage figures are — is entirely
//! machine-dependent and so cannot be asserted. A machine with local snapshots
//! and cached iCloud content shows a large gap; one without shows none. Run it
//! on any Mac to sanity-check FR-5:
//!
//! ```text
//! cargo run --example volume_probe
//! ```

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let v = sift::fs::volume::root()?;
    let gb = |b: u64| format!("{:>8.1} GB", b as f64 / 1e9);

    println!("volume:            {} ({})", v.name, v.fs_type);
    println!("device (st_dev):   {}", v.device);
    println!("total:             {}", gb(v.total));
    println!(
        "available (raw):   {}   <- what df reports",
        gb(v.available_raw)
    );
    println!(
        "available (impt):  {}   <- FR-5, what sift uses",
        gb(v.available_important)
    );
    println!("purgeable gap:     {}", gb(v.purgeable()));

    Ok(())
}
