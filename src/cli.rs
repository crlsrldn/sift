//! Command-line surface (PRD §7).
//!
//! The entire command tree is defined here up front, even though most
//! subcommands are stubs until their implementing PR. Two reasons: later PRs
//! fill in bodies rather than reshaping the CLI, and the generated `--help`
//! becomes reviewable documentation from the start.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

const AFTER_HELP: &str = "\
EXIT CODES:
  0   success (including a gated no-op run)
  1   unhandled runtime error
  2   invalid configuration
  3   required permission unavailable and no scanners could run
  4   circuit breaker tripped; nothing was actioned
  5   completed with one or more scanner errors
  64  CLI usage error

Nothing is deleted without an explicit `clean` and, unless --yes is given, a
confirmation. `sift` with no arguments reports and exits.";

#[derive(Debug, Parser)]
#[command(
    name = "sift",
    version,
    about = "Automated, safety-first disk reclamation for macOS",
    long_about = None,
    after_help = AFTER_HELP,
    disable_help_subcommand = true,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub global: GlobalArgs,
}

#[derive(Debug, Args, Clone)]
pub struct GlobalArgs {
    /// Emit machine-readable JSON instead of a human report.
    #[arg(long, global = true)]
    pub json: bool,

    /// Use an alternate config file.
    #[arg(long, value_name = "PATH", global = true, env = "SIFT_CONFIG")]
    pub config: Option<PathBuf>,

    /// Increase log verbosity. Overridden by SIFT_LOG.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Running under launchd. Enables JSON logging and the FR-20 preflight
    /// gates (battery, free space). Not intended for interactive use.
    #[arg(long, global = true, hide = true)]
    pub scheduled: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Report reclaimable space. Deletes nothing.
    Scan(ScanArgs),

    /// Scan, then quarantine what was found.
    Clean(CleanArgs),

    /// Hard-delete quarantined items past their TTL.
    Purge(PurgeArgs),

    /// Return a quarantined run to its original locations.
    Restore(RestoreArgs),

    /// Show the last run and a trend over recent history.
    Report(ReportArgs),

    /// Check permissions, tool availability, and config validity.
    Doctor,

    /// Install the scheduled LaunchAgent.
    Install,

    /// Remove the LaunchAgent, purge quarantine, and clean up.
    Uninstall,

    /// Configuration commands.
    #[command(subcommand)]
    Config(ConfigCommand),
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate the config file and print the effective merged configuration.
    Check,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Only run scanners matching this glob, e.g. `xcode-*`.
    #[arg(long, value_name = "GLOB")]
    pub only: Option<String>,

    /// Ask delegated tools how much they would reclaim.
    ///
    /// Off by default because it runs `brew`, `docker`, and `xcrun` — which
    /// costs seconds and lets those tools create their own cache directories.
    /// With it, delegated lines carry a real figure instead of "unknown".
    #[arg(long)]
    pub estimate_delegated: bool,
}

#[derive(Debug, Args)]
pub struct CleanArgs {
    /// Only run scanners matching this glob, e.g. `xcode-*`.
    #[arg(long, value_name = "GLOB")]
    pub only: Option<String>,

    /// Report exactly what would happen and then do nothing.
    #[arg(long)]
    pub dry_run: bool,

    /// Skip the confirmation prompt.
    ///
    /// This does not arm Destructive scanners — those additionally require both
    /// `enabled = true` and `max_risk = "destructive"` in config, and an
    /// interactive confirmation that --yes does not satisfy.
    #[arg(long)]
    pub yes: bool,

    /// Ask delegated tools how much they would reclaim before confirming.
    #[arg(long)]
    pub estimate_delegated: bool,
}

#[derive(Debug, Args)]
pub struct PurgeArgs {
    /// Hard-delete all quarantined items immediately, ignoring the TTL.
    #[arg(long)]
    pub now: bool,

    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// Run id to restore. A unique prefix is enough.
    pub run_id: String,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// How many days of history to include.
    #[arg(long, value_name = "N", default_value_t = 90)]
    pub days: u32,
}

impl Cli {
    /// `sift` with no subcommand means `sift scan` — dry-run is the default
    /// (Principle 2), so the zero-argument behaviour must be the reporting one.
    pub fn effective_command(self) -> (Command, GlobalArgs) {
        let global = self.global.clone();
        let command = self.command.unwrap_or(Command::Scan(ScanArgs {
            only: None,
            estimate_delegated: false,
        }));
        (command, global)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn every_prd_command_exists() {
        // PRD §7 command surface. If a command is renamed or dropped, this fails.
        let cmd = Cli::command();
        let names: Vec<String> = cmd
            .get_subcommands()
            .map(|s| s.get_name().to_string())
            .collect();

        for expected in [
            "scan",
            "clean",
            "purge",
            "restore",
            "report",
            "doctor",
            "install",
            "uninstall",
            "config",
        ] {
            assert!(names.contains(&expected.to_string()), "missing: {expected}");
        }
    }

    #[test]
    fn no_arguments_means_scan() {
        // Principle 2: dry-run is the default. `sift` alone must report, never act.
        let cli = Cli::parse_from(["sift"]);
        let (cmd, _) = cli.effective_command();
        assert!(matches!(cmd, Command::Scan(_)));
    }

    #[test]
    fn clean_requires_explicit_invocation() {
        // There is no flag that turns `scan` into `clean`. Deletion is reachable
        // only by naming it.
        let cli = Cli::parse_from(["sift", "scan"]);
        let (cmd, _) = cli.effective_command();
        assert!(matches!(cmd, Command::Scan(_)));
    }

    #[test]
    fn global_flags_work_before_and_after_the_subcommand() {
        for args in [
            vec!["sift", "--json", "scan"],
            vec!["sift", "scan", "--json"],
        ] {
            let cli = Cli::parse_from(&args);
            assert!(cli.global.json, "failed for {args:?}");
        }
    }

    #[test]
    fn scan_accepts_a_glob_filter() {
        let cli = Cli::parse_from(["sift", "scan", "--only", "xcode-*"]);
        match cli.effective_command().0 {
            Command::Scan(a) => assert_eq!(a.only.as_deref(), Some("xcode-*")),
            other => panic!("expected scan, got {other:?}"),
        }
    }

    #[test]
    fn clean_flags_parse() {
        let cli = Cli::parse_from(["sift", "clean", "--dry-run", "--yes"]);
        match cli.effective_command().0 {
            Command::Clean(a) => {
                assert!(a.dry_run);
                assert!(a.yes);
            }
            other => panic!("expected clean, got {other:?}"),
        }
    }

    #[test]
    fn report_defaults_to_ninety_days() {
        let cli = Cli::parse_from(["sift", "report"]);
        match cli.effective_command().0 {
            Command::Report(a) => assert_eq!(a.days, 90),
            other => panic!("expected report, got {other:?}"),
        }
    }

    #[test]
    fn restore_requires_a_run_id() {
        assert!(Cli::try_parse_from(["sift", "restore"]).is_err());
        assert!(Cli::try_parse_from(["sift", "restore", "0192abc"]).is_ok());
    }

    #[test]
    fn config_check_is_reachable() {
        let cli = Cli::parse_from(["sift", "config", "check"]);
        assert!(matches!(
            cli.effective_command().0,
            Command::Config(ConfigCommand::Check)
        ));
    }

    #[test]
    fn unknown_flags_and_commands_are_rejected() {
        assert!(Cli::try_parse_from(["sift", "--bogus"]).is_err());
        assert!(Cli::try_parse_from(["sift", "nonsense"]).is_err());
    }

    #[test]
    fn help_documents_the_exit_codes() {
        // The exit table is a public contract (spec §11); it belongs in --help,
        // not only in the docs.
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("EXIT CODES"));
        assert!(help.contains("circuit breaker"));
    }

    #[test]
    fn help_states_that_nothing_is_deleted_by_default() {
        let help = Cli::command().render_help().to_string();
        assert!(
            help.contains("Nothing is deleted"),
            "the default-safe behaviour must be visible in --help"
        );
    }
}
