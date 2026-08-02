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

/// What `--version` prints.
///
/// `CARGO_PKG_VERSION` alone cannot distinguish two builds from different
/// commits, and the documented install path is building from source — so the
/// commit is the part that actually answers "am I current?". Assembled in
/// `build.rs`; see there for why the tree state is included.
pub const VERSION: &str = env!("SIFT_VERSION");

#[derive(Debug, Parser)]
#[command(
    name = "sift",
    version = VERSION,
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
    Install(InstallArgs),

    /// Remove the LaunchAgent, purge quarantine, and clean up.
    Uninstall,

    /// Explain what a path is and whether sift would ever touch it.
    Explain(ExplainArgs),

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

    /// Also report scanners switched off in config.
    ///
    /// Shows what they hold without arming them. `scan` never acts, so this
    /// only affects what you are told; `clean` ignores these entirely whether
    /// or not the flag was given.
    #[arg(long)]
    pub include_disabled: bool,
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
pub struct ExplainArgs {
    /// The path to explain. `~` is expanded.
    pub path: PathBuf,
}

#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Show the plist and the launchctl command, and do neither.
    ///
    /// `install` loads a job into your launchd session, which persists across
    /// reboots. This shows exactly what that would be first.
    #[arg(long)]
    pub dry_run: bool,
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
            include_disabled: false,
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
    fn include_disabled_exists_on_scan_and_nowhere_else() {
        // Deliberately scan-only. `clean` has no way to be handed a context
        // that reports disabled scanners, so there is no argument the user
        // could pass — or a script could inherit — that turns a switched-off
        // scanner into a deletion.
        let cli = Cli::parse_from(["sift", "scan", "--include-disabled"]);
        match cli.effective_command().0 {
            Command::Scan(a) => assert!(a.include_disabled),
            other => panic!("expected scan, got {other:?}"),
        }

        assert!(
            Cli::try_parse_from(["sift", "clean", "--include-disabled"]).is_err(),
            "clean must not accept --include-disabled"
        );
    }

    #[test]
    fn include_disabled_is_off_unless_asked_for() {
        for args in [vec!["sift"], vec!["sift", "scan"]] {
            let cli = Cli::parse_from(&args);
            match cli.effective_command().0 {
                Command::Scan(a) => assert!(!a.include_disabled, "failed for {args:?}"),
                other => panic!("expected scan, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_version_identifies_the_build_not_just_the_crate() {
        // `0.1.0` alone cannot answer "am I running the current code?", which
        // is the question that matters when the install path is building from
        // source. Before this, the only way to tell was hashing the binary
        // against a fresh build.
        assert!(VERSION.starts_with(env!("CARGO_PKG_VERSION")), "{VERSION}");
        assert!(
            VERSION.len() > env!("CARGO_PKG_VERSION").len(),
            "the version carries no build detail: {VERSION}"
        );
        assert!(VERSION.contains("built "), "{VERSION}");
    }

    #[test]
    fn the_version_carries_a_well_formed_date() {
        // Not compared against today: the stamp is fixed when build.rs last
        // ran, which may be days before a test run. The shape is what proves
        // the date arithmetic produced a date at all — `civil_from_days` has
        // its own tests for whether it is the right one.
        let date = VERSION
            .split("built ")
            .nth(1)
            .and_then(|s| s.split(')').next())
            .unwrap_or_else(|| panic!("no build date in {VERSION}"));

        let parts: Vec<&str> = date.split('-').collect();
        assert_eq!(parts.len(), 3, "expected YYYY-MM-DD, got `{date}`");
        assert_eq!(parts[0].len(), 4, "{date}");

        let year: i64 = parts[0].parse().unwrap_or_else(|_| panic!("{date}"));
        let month: u32 = parts[1].parse().unwrap_or_else(|_| panic!("{date}"));
        let day: u32 = parts[2].parse().unwrap_or_else(|_| panic!("{date}"));

        // A broken epoch conversion lands in 1970 or far in the future; a
        // broken month/day calculation escapes these ranges.
        assert!((2024..=2100).contains(&year), "{date}");
        assert!((1..=12).contains(&month), "{date}");
        assert!((1..=31).contains(&day), "{date}");
    }

    #[test]
    fn a_commit_is_named_when_one_is_knowable() {
        // In a git checkout the hash must be there. From a source tarball it
        // legitimately cannot be, and build.rs omits it rather than inventing
        // one — so this only asserts when `.git` is present.
        if !std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".git")
            .exists()
        {
            return;
        }

        let inside = VERSION
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(','))
            .map(|(sha, _)| sha)
            .unwrap_or_else(|| panic!("no commit in {VERSION}"));

        let sha = inside.strip_suffix("-dirty").unwrap_or(inside);
        assert_eq!(sha.len(), 7, "expected a short hash, got `{sha}`");
        assert!(
            sha.chars().all(|c| c.is_ascii_hexdigit()),
            "not a hash: `{sha}`"
        );
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
