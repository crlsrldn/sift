//! Scanner framework: the trait, the registry, and isolated parallel execution
//! (FR-1, FR-2, FR-3, spec §4).
//!
//! # The central guarantee
//!
//! **One scanner cannot take down a run** (FR-2). A scanner that returns an
//! error, or panics, is recorded and the run continues with everything else.
//! That is not politeness — `sift` runs unattended at 03:00, and a run that
//! aborts because one scanner tripped over an unexpected directory layout is a
//! run that silently stops reclaiming anything.
//!
//! Isolation is enforced two ways:
//!
//! - `Scanner::scan` returns [`ScannerError`], which has no `From` impl into
//!   [`SiftError`]. A scanner *cannot* return a run-fatal error; the type
//!   system prevents it rather than review catching it.
//! - Every scanner runs inside `catch_unwind`, so a panic in scanner code — or
//!   in a library it calls — becomes a recorded error instead of a dead process.

use crate::caps::Capabilities;
use crate::config::Config;
use crate::fs::VolumeInfo;
use crate::risk::Risk;
use crate::ScannerError;
use chrono::{DateTime, Local};
use globset::GlobSet;
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;

/// Everything a scanner is allowed to know about the run.
///
/// Deliberately read-only and shared: a scanner cannot mutate global state, so
/// scanners cannot interfere with each other and running them in parallel is
/// sound by construction.
pub struct ScanCtx {
    pub config: Arc<Config>,
    pub now: DateTime<Local>,
    pub root_volume: VolumeInfo,
    pub caps: Capabilities,
    pub excludes: GlobSet,
    /// Whether delegated scanners may spawn their tool to size a candidate.
    ///
    /// **Off by default, and that default is load-bearing.** Sizing means
    /// running `brew cleanup --dry-run` and `docker system df`, which costs
    /// ~4 seconds against M4's 15-second budget for a whole volume, and lets
    /// those tools create their own cache directories — a side effect FR-1
    /// forbids. `--estimate-delegated` opts into both costs knowingly.
    pub estimate_delegated: bool,
    /// Whether scanners switched off in config should still be *reported*.
    ///
    /// `enabled = false` was doing two unrelated jobs: "never act on this" and
    /// "never tell me about this". Only the first is what anyone sets it for.
    /// A user who disables the delegated scanners to keep the nightly run
    /// reversible should not thereby lose the ability to see what they hold —
    /// and since `scan` never acts (Principle 2), looking costs nothing.
    ///
    /// This overrides the `enabled` gate **only**. `max_risk` is a separate
    /// axis with its own meaning, and a risk-gated scanner stays skipped and
    /// says so. Anything found this way lands in
    /// [`ScanReport::disabled_candidates`], never in the actionable set.
    pub include_disabled: bool,
}

impl ScanCtx {
    pub fn new(
        config: Arc<Config>,
        root_volume: VolumeInfo,
        caps: Capabilities,
    ) -> crate::Result<Self> {
        let excludes = config.exclude_globs()?;
        Ok(Self {
            config,
            now: Local::now(),
            root_volume,
            caps,
            excludes,
            estimate_delegated: false,
            include_disabled: false,
        })
    }

    /// Opt into spawning delegated tools for size estimates.
    pub fn with_delegated_estimates(mut self, yes: bool) -> Self {
        self.estimate_delegated = yes;
        self
    }

    /// Opt into reporting scanners that config has switched off.
    pub fn with_disabled_included(mut self, yes: bool) -> Self {
        self.include_disabled = yes;
        self
    }

    /// Age in days of something last modified at `t`.
    pub fn age_days(&self, t: DateTime<Local>) -> i64 {
        (self.now - t).num_days()
    }

    /// A walker configured with this run's excludes and depth cap.
    pub fn walker(&self) -> crate::fs::Walker {
        crate::fs::Walker::with_device(self.root_volume.device)
            .max_depth(self.config.safety.max_walk_depth)
            .excludes(self.excludes.clone())
    }
}

/// What a candidate points at.
#[derive(Debug, Clone)]
pub enum Target {
    /// A path that can be quarantined by rename and later restored.
    Path(PathBuf),
    /// A command owned by another tool. Irreversible by nature, so it bypasses
    /// quarantine (FR-15) and is only permitted at Safe tier or behind an
    /// explicit opt-in.
    Delegated(DelegatedCmd),
    /// An APFS snapshot, thinned via `tmutil`.
    Snapshot(SnapshotRef),
    /// A path deleted outright, without staging.
    ///
    /// Only `trash` uses this: `~/.Trash` **is** the user's quarantine, and
    /// moving its contents into a second one would be theatre. The type exists
    /// so that irreversibility is a property the pipeline reads rather than a
    /// rule each scanner is trusted to remember.
    HardDelete(PathBuf),
}

impl Target {
    /// Whether this can be staged to quarantine and undone.
    pub fn is_reversible(&self) -> bool {
        matches!(self, Target::Path(_))
    }

    /// The path this would destroy outright, if any.
    pub fn hard_delete_path(&self) -> Option<&std::path::Path> {
        match self {
            Target::HardDelete(p) => Some(p),
            _ => None,
        }
    }

    pub fn display(&self) -> String {
        match self {
            Target::Path(p) => p.display().to_string(),
            Target::Delegated(c) => c.display(),
            Target::Snapshot(s) => s.name.clone(),
            Target::HardDelete(p) => p.display().to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DelegatedCmd {
    pub program: String,
    pub args: Vec<String>,
}

impl DelegatedCmd {
    pub fn new(program: impl Into<String>, args: &[&str]) -> Self {
        Self {
            program: program.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn display(&self) -> String {
        if self.args.is_empty() {
            self.program.clone()
        } else {
            format!("{} {}", self.program, self.args.join(" "))
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotRef {
    pub name: String,
    pub created: DateTime<Local>,
}

/// One thing a scanner believes is reclaimable.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub scanner: &'static str,
    pub target: Target,
    /// Allocated blocks, hard-link deduped (FR-6). An estimate — see
    /// `fs::size` on APFS clones.
    pub bytes_on_disk: u64,
    pub bytes_apparent: u64,
    pub last_modified: DateTime<Local>,
    pub risk: Risk,
    /// User-facing name, in their vocabulary (Principle 6):
    /// "iOS 16.4 device support bundle", not a path.
    pub label: String,
    /// Why this is a candidate: "not accessed in 142 days".
    pub reason: String,
}

impl Candidate {
    pub fn age_days(&self, now: DateTime<Local>) -> i64 {
        (now - self.last_modified).num_days()
    }
}

/// What a scanner needs in order to run (FR-27).
#[derive(Debug, Clone, Default)]
pub struct Requirements {
    pub fda: bool,
    pub tool: Option<&'static str>,
}

/// Why a scanner produced nothing.
///
/// Distinct from an error: a scanner that correctly determines it has nothing
/// to do, or cannot safely proceed, is working as designed (Principle 7).
#[derive(Debug, Clone)]
pub enum SkippedScanner {
    Disabled,
    RiskGated {
        risk: Risk,
        max: Risk,
    },
    NeedsFda,
    NeedsTool(&'static str),
    /// The scanner ran and declined to claim anything, with a reason.
    NothingToDo(String),
}

impl SkippedScanner {
    pub fn describe(&self) -> String {
        match self {
            SkippedScanner::Disabled => "disabled".into(),
            SkippedScanner::RiskGated { risk, max } => {
                format!("risk tier {risk} exceeds max_risk {max}")
            }
            SkippedScanner::NeedsFda => "needs Full Disk Access".into(),
            SkippedScanner::NeedsTool(t) => format!("`{t}` not installed"),
            SkippedScanner::NothingToDo(why) => why.clone(),
        }
    }
}

/// A scanner: an independent module with its own eligibility rules.
pub trait Scanner: Send + Sync {
    fn id(&self) -> &'static str;

    fn requirements(&self) -> Requirements {
        Requirements::default()
    }

    /// Find candidates. **Must have no side effects** (FR-1) — this runs on
    /// every `sift scan`, which the user is entitled to treat as read-only.
    fn scan(&self, ctx: &ScanCtx) -> std::result::Result<Vec<Candidate>, ScannerError>;

    /// What is permanently lost if this scanner acts.
    ///
    /// Required for every Destructive scanner and enforced by a test over the
    /// registry. `None` is only valid for Safe and Rebuildable tiers, where the
    /// answer is "nothing you cannot get back".
    ///
    /// This is the sentence a user reads immediately before typing the
    /// scanner's name to confirm, so it must say what they lose in their own
    /// terms — not what the scanner does.
    fn blast_radius(&self) -> Option<&'static str> {
        None
    }

    /// Whether `--estimate-delegated` can get a size out of this scanner's
    /// tool.
    ///
    /// Not every tool offers one. `brew cleanup --dry-run`, `docker system df`,
    /// and `simctl list --json` all report what they hold; `uv cache prune`,
    /// `pnpm store prune`, `yarn cache clean`, and `cargo-sweep` have no
    /// dry-run and no reporting mode, so there is nothing to ask.
    ///
    /// This exists so the report can tell "we did not ask" from "we asked and
    /// got nothing" from "there is no way to ask". Reporting the third as
    /// either of the first two sends the user off to re-run with a flag that
    /// cannot help — which is exactly what the footnote did before this
    /// existed.
    fn estimates_size(&self) -> bool {
        false
    }
}

/// Whether the registered scanner with this id can be asked for a size.
///
/// Looked up by id because the report holds candidates, not scanners. Unknown
/// ids answer `false`: a scanner nobody can find certainly cannot be asked.
pub fn scanner_estimates_size(id: &str) -> bool {
    registry()
        .find(id)
        .map(|s| s.estimates_size())
        .unwrap_or(false)
}

/// Everything one run produced.
#[derive(Debug, Default)]
pub struct ScanReport {
    pub candidates: Vec<Candidate>,
    /// What scanners disabled in config would have claimed, found only when
    /// `--include-disabled` was given.
    ///
    /// **A separate field, deliberately.** These must never be actioned, and
    /// the way to guarantee that is to keep them out of the collection every
    /// actioning path reads, rather than to remember a flag check at each one.
    /// `clean`, the filter chain, and quarantine all consume `candidates`;
    /// none of them can reach this by accident.
    pub disabled_candidates: Vec<Candidate>,
    pub errors: Vec<(&'static str, String)>,
    pub skipped: Vec<(&'static str, SkippedScanner)>,
    pub duration: std::time::Duration,
}

impl ScanReport {
    pub fn total_bytes(&self) -> u64 {
        self.candidates.iter().map(|c| c.bytes_on_disk).sum()
    }

    pub fn by_scanner(&self, id: &str) -> Vec<&Candidate> {
        self.candidates.iter().filter(|c| c.scanner == id).collect()
    }

    pub fn bytes_by_scanner(&self) -> std::collections::BTreeMap<&'static str, u64> {
        let mut m = std::collections::BTreeMap::new();
        for c in &self.candidates {
            *m.entry(c.scanner).or_insert(0) += c.bytes_on_disk;
        }
        m
    }

    /// Bytes held by scanners that are switched off.
    ///
    /// Kept out of [`total_bytes`](Self::total_bytes) on purpose: that figure
    /// answers "what would `sift clean` reclaim?", and the answer for a
    /// disabled scanner is nothing.
    pub fn disabled_bytes(&self) -> u64 {
        self.disabled_candidates
            .iter()
            .map(|c| c.bytes_on_disk)
            .sum()
    }

    /// Which disabled scanners reported something, in report order.
    pub fn disabled_scanners(&self) -> Vec<&'static str> {
        let mut ids: Vec<&'static str> =
            self.disabled_candidates.iter().map(|c| c.scanner).collect();
        ids.dedup();
        ids
    }

    pub fn had_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Scanners that were blocked by a missing capability, as opposed to being
    /// switched off. PRD §7 requires these are surfaced, not silently omitted.
    pub fn blocked(&self) -> Vec<(&'static str, &SkippedScanner)> {
        self.skipped
            .iter()
            .filter(|(_, s)| matches!(s, SkippedScanner::NeedsFda | SkippedScanner::NeedsTool(_)))
            .map(|(id, s)| (*id, s))
            .collect()
    }
}

/// The set of scanners available to a run.
pub struct Registry {
    scanners: Vec<Box<dyn Scanner>>,
}

impl Registry {
    /// The registered scanner with this id, if any.
    pub fn find(&self, id: &str) -> Option<&dyn Scanner> {
        self.scanners
            .iter()
            .find(|s| s.id() == id)
            .map(|s| s.as_ref())
    }

    /// The production registry. Scanners are added by their implementing PRs.
    pub fn new() -> Self {
        Self {
            scanners: Vec::new(),
        }
    }

    pub fn with(mut self, s: Box<dyn Scanner>) -> Self {
        self.scanners.push(s);
        self
    }

    pub fn ids(&self) -> Vec<&'static str> {
        self.scanners.iter().map(|s| s.id()).collect()
    }

    /// The declared blast radius for a scanner, if it has one.
    pub fn blast_radius_of(&self, id: &str) -> Option<&'static str> {
        self.scanners
            .iter()
            .find(|s| s.id() == id)
            .and_then(|s| s.blast_radius())
    }

    pub fn len(&self) -> usize {
        self.scanners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scanners.is_empty()
    }

    /// Run every eligible scanner in parallel, isolating failures.
    ///
    /// `only` is an optional glob over scanner ids (`--only xcode-*`).
    pub fn run(&self, ctx: &ScanCtx, only: Option<&GlobSet>) -> ScanReport {
        let start = std::time::Instant::now();

        let outcomes: Vec<Outcome> = self
            .scanners
            .par_iter()
            .filter(|s| only.map(|g| g.is_match(s.id())).unwrap_or(true))
            .map(|s| run_one(s.as_ref(), ctx))
            .collect();

        let mut report = ScanReport::default();
        for outcome in outcomes {
            match outcome {
                Outcome::Found(mut c) => report.candidates.append(&mut c),
                Outcome::FoundDisabled(mut c) => report.disabled_candidates.append(&mut c),
                Outcome::Skipped(id, why) => report.skipped.push((id, why)),
                Outcome::Failed(id, msg) => report.errors.push((id, msg)),
            }
        }

        // Largest first: the report's job is to answer "where did my disk go?"
        // and the answer is almost always the first two lines.
        report
            .candidates
            .sort_by_key(|c| std::cmp::Reverse(c.bytes_on_disk));
        report
            .disabled_candidates
            .sort_by_key(|c| std::cmp::Reverse(c.bytes_on_disk));
        report.duration = start.elapsed();
        report
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

enum Outcome {
    Found(Vec<Candidate>),
    /// Ran only because `--include-disabled` asked. Reportable, never
    /// actionable.
    FoundDisabled(Vec<Candidate>),
    Skipped(&'static str, SkippedScanner),
    Failed(&'static str, String),
}

fn run_one(s: &dyn Scanner, ctx: &ScanCtx) -> Outcome {
    let id = s.id();

    // Config gates first — cheapest, and a disabled scanner should not even be
    // asked about its requirements.
    let Some(cfg) = ctx.config.scanner(id) else {
        return Outcome::Skipped(id, SkippedScanner::NothingToDo("not configured".into()));
    };
    // `enabled = false` means "never act on this". Whether it also means
    // "never look" is the caller's choice: `scan` can ask for these to be
    // reported, and what comes back is quarantined into a field no actioning
    // path reads. The risk gate below still applies — that is a different axis
    // and this flag does not touch it.
    let disabled = !cfg.enabled;
    if disabled && !ctx.include_disabled {
        return Outcome::Skipped(id, SkippedScanner::Disabled);
    }
    if cfg.risk > ctx.config.general.max_risk {
        // A scanner that is *also* switched off is reported as switched off.
        // That is the state the user actually set, and `RiskGated`'s message
        // says the scanner is enabled — which would be a lie here, since only
        // `--include-disabled` let a disabled scanner reach this gate at all.
        return Outcome::Skipped(
            id,
            if disabled {
                SkippedScanner::Disabled
            } else {
                SkippedScanner::RiskGated {
                    risk: cfg.risk,
                    max: ctx.config.general.max_risk,
                }
            },
        );
    }

    // Capability gates. FR-27: skipped with a reason, never an error.
    let req = s.requirements();
    if req.fda && !ctx.caps.fda.is_granted() {
        return Outcome::Skipped(id, SkippedScanner::NeedsFda);
    }
    if let Some(tool) = req.tool {
        if !ctx.caps.has_tool(tool) {
            return Outcome::Skipped(id, SkippedScanner::NeedsTool(tool));
        }
    }

    // FR-2. A panic anywhere in scanner code — or in a crate it calls — must
    // not kill an unattended 03:00 run. AssertUnwindSafe is sound here because
    // ScanCtx is immutable and shared; there is no state a partial unwind could
    // leave inconsistent.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.scan(ctx)));

    match result {
        // A scanner that ran and claimed nothing is recorded too. PRD §7 says
        // skipped items are surfaced rather than silently omitted, and a
        // scanner that vanishes entirely from the report is indistinguishable
        // from one that was never registered. This does not appear in the human
        // report body — that would be noise — but it is in --json, so "did it
        // even look?" is answerable.
        Ok(Ok(candidates)) if candidates.is_empty() => Outcome::Skipped(
            id,
            SkippedScanner::NothingToDo("ran; nothing eligible".into()),
        ),
        Ok(Ok(candidates)) if disabled => Outcome::FoundDisabled(candidates),
        Ok(Ok(candidates)) => Outcome::Found(candidates),
        Ok(Err(e)) => {
            tracing::warn!(scanner = id, error = %e, "scanner failed");
            Outcome::Failed(id, e.to_string())
        }
        Err(panic) => {
            let msg = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panicked".into());
            tracing::error!(scanner = id, panic = %msg, "scanner panicked");
            Outcome::Failed(id, format!("panicked: {msg}"))
        }
    }
}

pub mod app_caches;
pub mod containers;
pub mod downloads;
pub mod homebrew;
pub mod ios_backups;
pub mod logs;
pub mod node;
pub mod python;
pub mod rust;
pub mod simulators;
pub mod snapshots;
pub mod trash;
pub mod xcode;

/// The production registry.
///
/// Scanners are registered by their implementing PR, so this list is an
/// accurate inventory of what actually works rather than an aspiration.
pub fn registry() -> Registry {
    Registry::new()
        .with(Box::new(xcode::DerivedData)) // S2
        .with(Box::new(xcode::DeviceSupport)) // S3
        .with(Box::new(xcode::Archives)) // S4 — Destructive, gated by max_risk
        .with(Box::new(rust::Targets)) // S6
        .with(Box::new(rust::CargoCache)) // S7
        .with(Box::new(app_caches::AppCaches)) // S14
        .with(Box::new(logs::Logs)) // S17
        .with(Box::new(simulators::Simulators)) // S5
        .with(Box::new(homebrew::Homebrew)) // S8
        .with(Box::new(containers::Containers)) // S9
        .with(Box::new(node::NodeCaches)) // S10
        .with(Box::new(python::PythonCaches)) // S11
        // Destructive tier. Registered so they appear in `doctor` and
        // `config check`; inert until BOTH config switches are set.
        .with(Box::new(snapshots::Snapshots)) // S1
        .with(Box::new(trash::Trash)) // S12
        .with(Box::new(downloads::Downloads)) // S13
        .with(Box::new(ios_backups::IosBackups)) // S15
}

/// Compile a `--only` glob into a set matching scanner ids.
pub fn only_filter(pattern: &str) -> crate::Result<GlobSet> {
    let glob = globset::Glob::new(pattern)
        .map_err(|e| crate::SiftError::Usage(format!("--only `{pattern}`: {e}")))?;
    let mut b = globset::GlobSetBuilder::new();
    b.add(glob);
    b.build()
        .map_err(|e| crate::SiftError::Usage(format!("--only `{pattern}`: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Capabilities;

    fn ctx_with(cfg: Config) -> ScanCtx {
        ScanCtx::new(
            Arc::new(cfg),
            crate::fs::volume::root().unwrap(),
            Capabilities::probe(),
        )
        .unwrap()
    }

    struct Ok1;
    impl Scanner for Ok1 {
        fn id(&self) -> &'static str {
            "logs"
        }
        fn scan(&self, ctx: &ScanCtx) -> std::result::Result<Vec<Candidate>, ScannerError> {
            Ok(vec![Candidate {
                scanner: "logs",
                target: Target::Path("/tmp/x".into()),
                bytes_on_disk: 1000,
                bytes_apparent: 1000,
                last_modified: ctx.now,
                risk: Risk::Safe,
                label: "test".into(),
                reason: "test".into(),
            }])
        }
    }

    struct Failing;
    impl Scanner for Failing {
        fn id(&self) -> &'static str {
            "app-caches"
        }
        fn scan(&self, _: &ScanCtx) -> std::result::Result<Vec<Candidate>, ScannerError> {
            Err(ScannerError::new("app-caches", anyhow::anyhow!("boom")))
        }
    }

    struct Panicking;
    impl Scanner for Panicking {
        fn id(&self) -> &'static str {
            "homebrew"
        }
        fn scan(&self, _: &ScanCtx) -> std::result::Result<Vec<Candidate>, ScannerError> {
            panic!("scanner exploded")
        }
    }

    #[test]
    fn a_failing_scanner_does_not_stop_the_run() {
        // FR-2. The other scanner must still produce its candidate.
        let r = Registry::new().with(Box::new(Failing)).with(Box::new(Ok1));
        let report = r.run(&ctx_with(Config::default()), None);

        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].0, "app-caches");
        assert_eq!(report.candidates.len(), 1, "the healthy scanner still ran");
    }

    #[test]
    fn a_panicking_scanner_does_not_kill_the_process() {
        // The reason catch_unwind is here: an unattended 03:00 run must survive
        // a panic in scanner code or in a crate it calls.
        let r = Registry::new()
            .with(Box::new(Panicking))
            .with(Box::new(Ok1));
        let report = r.run(&ctx_with(Config::default()), None);

        assert_eq!(report.errors.len(), 1);
        assert!(
            report.errors[0].1.contains("panicked"),
            "{:?}",
            report.errors
        );
        assert!(report.errors[0].1.contains("scanner exploded"));
        assert_eq!(report.candidates.len(), 1);
    }

    #[test]
    fn a_disabled_scanner_never_runs() {
        let cfg = Config::parse("[scanners.logs]\nenabled = false\n").unwrap();
        let r = Registry::new().with(Box::new(Ok1));
        let report = r.run(&ctx_with(cfg), None);

        assert!(report.candidates.is_empty());
        assert!(matches!(report.skipped[0].1, SkippedScanner::Disabled));
    }

    #[test]
    fn a_risk_gated_scanner_never_runs() {
        // The two-switch model, enforced at execution rather than only in
        // config: even a scanner that slipped through must not run.
        struct Destructive;
        impl Scanner for Destructive {
            fn id(&self) -> &'static str {
                "trash"
            }
            fn scan(&self, _: &ScanCtx) -> std::result::Result<Vec<Candidate>, ScannerError> {
                panic!("must never be called")
            }
        }

        let cfg = Config::parse("[scanners.trash]\nenabled = true\n").unwrap();
        let r = Registry::new().with(Box::new(Destructive));
        let report = r.run(&ctx_with(cfg), None);

        assert!(report.candidates.is_empty());
        assert!(report.errors.is_empty(), "it must not even be invoked");
        assert!(matches!(
            report.skipped[0].1,
            SkippedScanner::RiskGated { .. }
        ));
    }

    /// A disabled scanner that would claim something, if anyone let it.
    struct DisabledFinder;
    impl Scanner for DisabledFinder {
        fn id(&self) -> &'static str {
            "homebrew"
        }
        fn scan(&self, ctx: &ScanCtx) -> std::result::Result<Vec<Candidate>, ScannerError> {
            Ok(vec![Candidate {
                scanner: "homebrew",
                target: Target::Path("/tmp/disabled-thing".into()),
                bytes_on_disk: 5000,
                bytes_apparent: 5000,
                last_modified: ctx.now,
                risk: Risk::Safe,
                label: "disabled finding".into(),
                reason: "test".into(),
            }])
        }
    }

    #[test]
    fn a_disabled_scanner_does_not_run_by_default() {
        let cfg = Config::parse("[scanners.homebrew]\nenabled = false\n").unwrap();
        let r = Registry::new().with(Box::new(DisabledFinder));
        let report = r.run(&ctx_with(cfg), None);

        assert!(report.candidates.is_empty());
        assert!(
            report.disabled_candidates.is_empty(),
            "nobody asked to look"
        );
        assert!(matches!(report.skipped[0].1, SkippedScanner::Disabled));
    }

    #[test]
    fn include_disabled_reports_but_never_makes_actionable() {
        // The whole point of the flag, and the whole risk of it. `enabled =
        // false` must keep meaning "never act" even while it stops meaning
        // "never look".
        let cfg = Config::parse("[scanners.homebrew]\nenabled = false\n").unwrap();
        let r = Registry::new().with(Box::new(DisabledFinder));
        let report = r.run(&ctx_with(cfg).with_disabled_included(true), None);

        // Reported...
        assert_eq!(report.disabled_candidates.len(), 1);
        assert_eq!(report.disabled_bytes(), 5000);
        assert_eq!(report.disabled_scanners(), vec!["homebrew"]);

        // ...and unreachable by anything that acts. `clean` consumes
        // `candidates` and `total_bytes`; both must be untouched.
        assert!(
            report.candidates.is_empty(),
            "a disabled scanner's findings must never enter the actionable set"
        );
        assert_eq!(
            report.total_bytes(),
            0,
            "disabled bytes must not inflate the figure that describes what clean would do"
        );
        assert!(report.bytes_by_scanner().is_empty());
        assert!(report.by_scanner("homebrew").is_empty());
    }

    #[test]
    fn include_disabled_does_not_override_the_risk_gate() {
        // The flag overrides one gate, not all of them. A destructive scanner
        // stays unrun whichever way `enabled` is set.
        struct DestructiveDisabled;
        impl Scanner for DestructiveDisabled {
            fn id(&self) -> &'static str {
                "trash"
            }
            fn scan(&self, _: &ScanCtx) -> std::result::Result<Vec<Candidate>, ScannerError> {
                panic!("must never be called")
            }
        }

        let cfg = Config::parse("[scanners.trash]\nenabled = false\n").unwrap();
        let r = Registry::new().with(Box::new(DestructiveDisabled));
        let report = r.run(&ctx_with(cfg).with_disabled_included(true), None);

        assert!(report.disabled_candidates.is_empty());
        assert!(report.errors.is_empty(), "it must not even be invoked");
    }

    #[test]
    fn a_disabled_and_risk_gated_scanner_is_reported_as_disabled() {
        // `RiskGated`'s rendering tells the user the scanner is enabled and
        // only the tier is unarmed. For a scanner that is *also* switched off
        // that would be false — and only --include-disabled lets one reach
        // this gate at all.
        struct DestructiveDisabled;
        impl Scanner for DestructiveDisabled {
            fn id(&self) -> &'static str {
                "trash"
            }
            fn scan(&self, _: &ScanCtx) -> std::result::Result<Vec<Candidate>, ScannerError> {
                panic!("must never be called")
            }
        }

        let cfg = Config::parse("[scanners.trash]\nenabled = false\n").unwrap();
        let r = Registry::new().with(Box::new(DestructiveDisabled));
        let report = r.run(&ctx_with(cfg).with_disabled_included(true), None);

        assert!(
            matches!(report.skipped[0].1, SkippedScanner::Disabled),
            "got {:?}",
            report.skipped[0].1
        );

        // ...while an enabled one above the ceiling still reports the tier.
        let cfg = Config::parse("[scanners.trash]\nenabled = true\n").unwrap();
        let r = Registry::new().with(Box::new(DestructiveDisabled));
        let report = r.run(&ctx_with(cfg).with_disabled_included(true), None);
        assert!(matches!(
            report.skipped[0].1,
            SkippedScanner::RiskGated { .. }
        ));
    }

    #[test]
    fn only_scanners_with_a_reporting_tool_claim_they_can_be_asked() {
        // `--estimate-delegated` can only get a figure where the tool offers
        // one. `brew cleanup --dry-run`, `docker system df` and
        // `simctl list --json` do; `uv cache prune`, `pnpm store prune`,
        // `yarn cache clean` and `cargo-sweep` have no dry-run and no
        // reporting mode at all.
        //
        // Getting this list wrong is not cosmetic: the report uses it to
        // decide whether to tell the user that re-running with the flag would
        // help, and for these four it never would.
        for id in ["homebrew", "containers", "simulators"] {
            assert!(
                scanner_estimates_size(id),
                "`{id}` should be able to report a size"
            );
        }
        for id in [
            "python-caches",
            "node-caches",
            "rust-targets",
            "cargo-cache",
        ] {
            assert!(
                !scanner_estimates_size(id),
                "`{id}` has no tool that reports a size"
            );
        }
    }

    #[test]
    fn an_unregistered_scanner_cannot_be_asked() {
        assert!(!scanner_estimates_size("not-a-scanner"));
    }

    #[test]
    fn a_scanner_missing_a_required_tool_is_skipped_not_failed() {
        // FR-27: absence of an optional tool is a normal state.
        struct NeedsGhost;
        impl Scanner for NeedsGhost {
            fn id(&self) -> &'static str {
                "containers"
            }
            fn requirements(&self) -> Requirements {
                Requirements {
                    fda: false,
                    tool: Some("definitely-not-installed"),
                }
            }
            fn scan(&self, _: &ScanCtx) -> std::result::Result<Vec<Candidate>, ScannerError> {
                panic!("must never be called")
            }
        }

        let r = Registry::new().with(Box::new(NeedsGhost));
        let report = r.run(&ctx_with(Config::default()), None);

        assert!(report.errors.is_empty(), "a missing tool is not an error");
        assert!(matches!(report.skipped[0].1, SkippedScanner::NeedsTool(_)));
        assert_eq!(report.blocked().len(), 1);
    }

    #[test]
    fn candidates_are_sorted_largest_first() {
        struct Multi;
        impl Scanner for Multi {
            fn id(&self) -> &'static str {
                "logs"
            }
            fn scan(&self, ctx: &ScanCtx) -> std::result::Result<Vec<Candidate>, ScannerError> {
                Ok([500u64, 9000, 1200]
                    .iter()
                    .map(|b| Candidate {
                        scanner: "logs",
                        target: Target::Path("/tmp/x".into()),
                        bytes_on_disk: *b,
                        bytes_apparent: *b,
                        last_modified: ctx.now,
                        risk: Risk::Safe,
                        label: "x".into(),
                        reason: "x".into(),
                    })
                    .collect())
            }
        }

        let r = Registry::new().with(Box::new(Multi));
        let report = r.run(&ctx_with(Config::default()), None);
        let sizes: Vec<u64> = report.candidates.iter().map(|c| c.bytes_on_disk).collect();
        assert_eq!(sizes, vec![9000, 1200, 500]);
    }

    #[test]
    fn only_filter_selects_a_subset() {
        let r = Registry::new().with(Box::new(Ok1)).with(Box::new(Failing));
        let filter = only_filter("logs").unwrap();
        let report = r.run(&ctx_with(Config::default()), Some(&filter));

        assert_eq!(report.candidates.len(), 1);
        assert!(report.errors.is_empty(), "app-caches should not have run");
    }

    #[test]
    fn only_filter_supports_globs() {
        let f = only_filter("xcode-*").unwrap();
        assert!(f.is_match("xcode-derived"));
        assert!(f.is_match("xcode-devicesupport"));
        assert!(!f.is_match("logs"));
    }

    #[test]
    fn an_invalid_only_pattern_is_a_usage_error() {
        let e = only_filter("[").unwrap_err();
        assert_eq!(e.exit_code(), crate::ExitCode::Usage);
    }

    #[test]
    fn delegated_targets_are_not_reversible() {
        // FR-15: delegated commands bypass quarantine because they cannot be
        // undone. The type answers this, so the pipeline cannot get it wrong.
        assert!(Target::Path("/tmp/x".into()).is_reversible());
        assert!(!Target::Delegated(DelegatedCmd::new("brew", &["cleanup"])).is_reversible());
        assert!(!Target::Snapshot(SnapshotRef {
            name: "s".into(),
            created: Local::now()
        })
        .is_reversible());
    }

    #[test]
    fn bytes_by_scanner_groups_correctly() {
        let r = Registry::new().with(Box::new(Ok1));
        let report = r.run(&ctx_with(Config::default()), None);
        assert_eq!(report.bytes_by_scanner().get("logs"), Some(&1000));
        assert_eq!(report.total_bytes(), 1000);
    }

    #[test]
    fn an_empty_registry_produces_an_empty_report() {
        let report = Registry::new().run(&ctx_with(Config::default()), None);
        assert!(report.candidates.is_empty());
        assert!(report.errors.is_empty());
        assert!(!report.had_errors());
    }
}
