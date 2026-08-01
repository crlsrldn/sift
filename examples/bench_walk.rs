//! Walk throughput and peak memory, for validating the PRD §9 metrics.
//!
//! M4 states "500 GB volume in under 15 seconds" and M5 "peak RSS under 100 MB
//! on a 2 M-file walk". Both are really about inode count: a volume of large
//! files walks fast regardless of size. This reports files/sec so the figure
//! can be extrapolated honestly rather than guessed at.
fn main() {
    let root = std::env::args().nth(1).expect("usage: bench_walk <path>");
    let path = std::path::Path::new(&root);

    let streaming = std::env::args().nth(2).as_deref() != Some("--collect");

    let start = std::time::Instant::now();
    let walker = sift::fs::Walker::new(path).unwrap();

    let (m, files, skipped) = if streaming {
        let mut measurer = sift::fs::size::Measurer::new();
        let summary = walker.visit(path, |_, meta, _| measurer.add(meta)).unwrap();
        (measurer.finish(), summary.files, summary.total_skipped())
    } else {
        // The old collecting path, kept so the two can be compared directly.
        let result = walker.walk(path).unwrap();
        let files = result.entries.len() as u64;
        let skipped = result.skipped.len() as u64;
        (sift::fs::size::measure_result(&result), files, skipped)
    };
    let elapsed = start.elapsed();
    let files_f = files as f64;
    let files = files_f;

    println!(
        "  mode         {}",
        if streaming { "streaming" } else { "collecting" }
    );
    println!("  path         {}", path.display());
    println!("  files        {}", files_f as u64);
    println!("  skipped      {skipped}");
    println!("  bytes        {:.2} GB", m.bytes_on_disk as f64 / 1e9);
    println!("  elapsed      {:.2}s", elapsed.as_secs_f64());
    println!(
        "  throughput   {:.0} files/sec",
        files / elapsed.as_secs_f64()
    );
    println!("  peak RSS     {:.1} MB", peak_rss_mb());
}

fn peak_rss_mb() -> f64 {
    // SAFETY: getrusage with a valid out-pointer; no preconditions.
    unsafe {
        let mut u: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut u) == 0 {
            // macOS reports ru_maxrss in BYTES, unlike Linux.
            u.ru_maxrss as f64 / 1e6
        } else {
            0.0
        }
    }
}
