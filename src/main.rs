//! `sift` binary entry point.
//!
//! Deliberately thin: parse arguments, initialize logging, load config,
//! dispatch, and translate a [`SiftError`] into a process exit code. All real
//! work lives in the library so `tests/` can exercise it directly.

use clap::Parser;
use sift::cli::{Cli, Command, ConfigCommand, GlobalArgs};
use sift::commands::{clean, config_check, doctor, explain, install, purge, report, restore, scan};
use sift::config::Config;
use sift::logging::{self, LogFormat};
use sift::{ExitCode, Result};

fn main() {
    // clap exits 2 on parse failure by default; spec §11 says usage errors are
    // 64, so parse errors are intercepted and re-coded rather than left to clap.
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            let code = match e.kind() {
                clap::error::ErrorKind::DisplayHelp
                | clap::error::ErrorKind::DisplayVersion
                | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
                    ExitCode::Success
                }
                _ => ExitCode::Usage,
            };
            std::process::exit(code.as_i32());
        }
    };

    let (command, global) = cli.effective_command();
    logging::init(LogFormat::for_run(global.scheduled), global.verbose);

    match run(command, &global) {
        Ok(()) => std::process::exit(ExitCode::Success.as_i32()),
        Err(err) => {
            let code = err.exit_code();
            // Errors go to stderr as plain text regardless of log format: a
            // failure the user must act on should never be buried in a filtered
            // log stream.
            eprintln!("sift: {err}");
            std::process::exit(code.as_i32());
        }
    }
}

fn run(command: Command, global: &GlobalArgs) -> Result<()> {
    // Config is loaded for every command, including the stubs. An invalid
    // config should fail with exit 2 the moment sift runs, not later when the
    // command that happens to read a particular key finally lands.
    let config = match &global.config {
        Some(path) => Config::load_from(path)?,
        None => Config::load()?,
    };

    match command {
        Command::Config(ConfigCommand::Check) => config_check::run(&config, global.json),

        Command::Scan(a) => scan::run(
            &config,
            a.only.as_deref(),
            a.estimate_delegated,
            global.json,
        ),
        Command::Clean(a) => clean::run(
            &config,
            a.only.as_deref(),
            a.dry_run,
            a.yes,
            a.estimate_delegated,
            global.scheduled,
            global.json,
        ),
        Command::Purge(a) => purge::run(&config, a.now, a.yes, global.json),
        Command::Restore(a) => restore::run(&a.run_id, global.json),
        Command::Report(a) => report::run(a.days, global.json),
        Command::Doctor => doctor::run(&config, global.json),
        Command::Explain(a) => explain::run(&config, &a.path, global.json),
        Command::Install(a) => install::install_cmd(&config, a.dry_run, global.json),
        Command::Uninstall => install::uninstall_cmd(global.json),
    }
}
