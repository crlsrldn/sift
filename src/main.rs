//! `sift` — an automated, safety-first disk reclamation agent for macOS.
//!
//! This is the PR-01 scaffold. The real command surface arrives in PR-04, where
//! this hand-rolled argument handling is replaced wholesale by `clap` derive
//! definitions covering every command in PRD §7.

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
sift — automated, safety-first disk reclamation for macOS

USAGE:
    sift [OPTIONS]

OPTIONS:
    -V, --version    Print version information
    -h, --help       Print this message

This binary is a scaffold. No scanning or deletion capability is implemented yet.
";

fn main() {
    // Minimal, dependency-free argument handling. `clap` is already a declared
    // dependency but is not wired up until PR-04; introducing it here would mean
    // building the command tree twice.
    let mut args = std::env::args().skip(1);

    match args.next().as_deref() {
        Some("-V") | Some("--version") => println!("sift {VERSION}"),
        Some("-h") | Some("--help") => print!("{USAGE}"),
        None => println!("sift {VERSION}"),
        Some(other) => {
            eprintln!("sift: unrecognized argument `{other}`");
            eprintln!("Try `sift --help`.");
            // Exit 64 is the CLI usage error in the spec §11 exit-code table.
            // The full taxonomy lands in PR-02.
            std::process::exit(64);
        }
    }
}
