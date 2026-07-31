//! `sift` binary entry point.
//!
//! Deliberately thin: it parses arguments, initializes logging, dispatches, and
//! translates a [`SiftError`] into a process exit code. All real work lives in
//! the library so that `tests/` can exercise it directly.
//!
//! The hand-rolled argument handling here is replaced by `clap` in PR-04, which
//! introduces the full command surface from PRD §7.

use sift::{
    logging::{self, LogFormat},
    ExitCode, SiftError,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
sift — automated, safety-first disk reclamation for macOS

USAGE:
    sift [OPTIONS]

OPTIONS:
    -V, --version    Print version information
    -v, --verbose    Increase log verbosity
    -h, --help       Print this message

ENVIRONMENT:
    SIFT_LOG         Log filter, e.g. `sift=debug` (overrides --verbose)

This binary is a scaffold. No scanning or deletion capability is implemented yet.
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");
    let scheduled = args.iter().any(|a| a == "--scheduled");

    logging::init(LogFormat::for_run(scheduled), verbose);

    match run(&args) {
        Ok(()) => std::process::exit(ExitCode::Success.as_i32()),
        Err(err) => {
            let code = err.exit_code();
            // Errors go to stderr as plain text regardless of log format: a
            // failure the user must act on should never be buried in a filtered
            // log stream or swallowed by a level setting.
            eprintln!("sift: {err}");
            std::process::exit(code.as_i32());
        }
    }
}

fn run(args: &[String]) -> sift::Result<()> {
    let positional: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !matches!(*a, "-v" | "--verbose" | "--scheduled"))
        .collect();

    match positional.first().copied() {
        Some("-V") | Some("--version") => {
            println!("sift {VERSION}");
            Ok(())
        }
        Some("-h") | Some("--help") => {
            print!("{USAGE}");
            Ok(())
        }
        None => {
            println!("sift {VERSION}");
            Ok(())
        }
        Some(other) => Err(SiftError::Usage(format!(
            "unrecognized argument `{other}`; try `sift --help`"
        ))),
    }
}
