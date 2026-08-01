//! Preconditions for a scheduled run (FR-20, spec §9).
//!
//! Evaluated in `--scheduled` mode **before any scan**. A gated run exits 0 and
//! records why — launchd must not see a failure, because declining to work is
//! the correct outcome, not an error.

use crate::config::Config;
use crate::fs::VolumeInfo;
use crate::report::human::size;
use chrono::{DateTime, Local};

/// Why a scheduled run declined to do anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gated {
    /// Free space is above the floor. Doing the work when it does not matter
    /// spends I/O and risk for nothing.
    PlentyOfSpace { free: u64, floor: u64 },
    /// On battery, below the threshold.
    LowBattery { percent: u8, threshold: u8 },
}

impl Gated {
    pub fn describe(&self) -> String {
        match self {
            Gated::PlentyOfSpace { free, floor } => {
                format!("{} free is above the {} floor", size(*free), size(*floor))
            }
            Gated::LowBattery { percent, threshold } => {
                format!("on battery at {percent}%, below the {threshold}% threshold")
            }
        }
    }
}

/// Power state, as far as the gate cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Power {
    /// On mains. Battery level is irrelevant.
    Ac,
    Battery(u8),
    /// Could not be determined — a desktop, or `pmset` output we do not
    /// recognise. Treated as AC: refusing to run because we could not read a
    /// battery that may not exist would silently disable the tool on every
    /// Mac mini and Studio.
    Unknown,
}

/// Everything the gates need, injected so they are testable without a machine
/// in a particular state.
#[derive(Debug, Clone)]
pub struct GateInputs {
    pub power: Power,
    pub free_important: u64,
    pub last_successful_run: Option<DateTime<Local>>,
    pub now: DateTime<Local>,
}

/// Decide whether a scheduled run should proceed.
pub fn evaluate(cfg: &Config, inputs: &GateInputs) -> Option<Gated> {
    // Battery first: no amount of disk pressure justifies draining a laptop the
    // user is carrying.
    if let Power::Battery(percent) = inputs.power {
        let threshold = cfg.schedule.skip_on_battery_below;
        if percent < threshold {
            return Some(Gated::LowBattery { percent, threshold });
        }
    }

    let floor = cfg.general.free_space_floor.bytes();
    if inputs.free_important > floor {
        // Resolution of PRD Open Question 2.
        //
        // The floor is elegant — do the work when it matters — but it means the
        // first run after a long comfortable period is the biggest and riskiest.
        // This overrides it once runs have not happened for a while, so work
        // stays incremental instead of accumulating into one large action.
        let max_days = cfg.schedule.max_days_between_runs as i64;
        let overdue = match inputs.last_successful_run {
            Some(last) => (inputs.now - last).num_days() >= max_days,
            // Never run before. Do the first one rather than waiting for the
            // disk to fill.
            None => true,
        };
        if !overdue {
            return Some(Gated::PlentyOfSpace {
                free: inputs.free_important,
                floor,
            });
        }
    }

    None
}

/// Read power state from `pmset -g batt`.
///
/// Output looks like:
///
/// ```text
/// Now drawing from 'Battery Power'
///  -InternalBattery-0 (id=...)  87%; discharging; 4:32 remaining present: true
/// ```
///
/// A desktop prints only `Now drawing from 'AC Power'` with no battery line.
pub fn read_power() -> Power {
    let out = crate::action::delegate::probe(
        "pmset",
        &["-g", "batt"],
        std::time::Duration::from_secs(10),
    );
    let crate::action::delegate::Outcome::Ok { stdout, .. } = out else {
        return Power::Unknown;
    };
    parse_power(&stdout)
}

pub fn parse_power(stdout: &str) -> Power {
    if stdout.contains("'AC Power'") {
        return Power::Ac;
    }
    if !stdout.contains("'Battery Power'") {
        return Power::Unknown;
    }
    for token in stdout.split_whitespace() {
        if let Some(num) = token.trim_end_matches(';').strip_suffix('%') {
            if let Ok(p) = num.parse::<u8>() {
                return Power::Battery(p);
            }
        }
    }
    // On battery but the percentage is unparseable. Assume it is low rather
    // than high: erring toward not running is the cheap mistake.
    Power::Battery(0)
}

/// Gather real inputs.
pub fn inputs(volume: &VolumeInfo, last_successful_run: Option<DateTime<Local>>) -> GateInputs {
    GateInputs {
        power: read_power(),
        free_important: volume.available_important,
        last_successful_run,
        now: Local::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn base(free: u64) -> GateInputs {
        GateInputs {
            power: Power::Ac,
            free_important: free,
            last_successful_run: Some(Local::now()),
            now: Local::now(),
        }
    }

    const GB: u64 = 1_073_741_824;

    #[test]
    fn a_full_disk_on_mains_proceeds() {
        let g = evaluate(&Config::default(), &base(5 * GB));
        assert_eq!(g, None);
    }

    #[test]
    fn a_comfortable_disk_is_gated() {
        // FR-20: do the work when it matters, not for its own sake.
        let g = evaluate(&Config::default(), &base(200 * GB));
        assert!(matches!(g, Some(Gated::PlentyOfSpace { .. })));
    }

    #[test]
    fn a_low_battery_is_gated_even_with_a_full_disk() {
        // No amount of disk pressure justifies draining a laptop.
        let mut i = base(GB);
        i.power = Power::Battery(15);
        assert!(matches!(
            evaluate(&Config::default(), &i),
            Some(Gated::LowBattery { .. })
        ));
    }

    #[test]
    fn a_charged_battery_proceeds() {
        let mut i = base(GB);
        i.power = Power::Battery(80);
        assert_eq!(evaluate(&Config::default(), &i), None);
    }

    #[test]
    fn an_unknown_power_state_proceeds() {
        // A desktop has no battery. Refusing to run because we could not read
        // one would silently disable the tool on every Mac mini and Studio.
        let mut i = base(GB);
        i.power = Power::Unknown;
        assert_eq!(evaluate(&Config::default(), &i), None);
    }

    #[test]
    fn an_overdue_run_overrides_the_free_space_floor() {
        // PRD Open Question 2. Without this, a comfortable machine accumulates
        // months of work into one large, risky first action.
        let mut i = base(500 * GB);
        i.last_successful_run = Some(Local::now() - Duration::days(20));
        assert_eq!(
            evaluate(&Config::default(), &i),
            None,
            "a run 20 days old should override the 14-day window"
        );
    }

    #[test]
    fn a_recent_run_does_not_override_the_floor() {
        let mut i = base(500 * GB);
        i.last_successful_run = Some(Local::now() - Duration::days(3));
        assert!(matches!(
            evaluate(&Config::default(), &i),
            Some(Gated::PlentyOfSpace { .. })
        ));
    }

    #[test]
    fn a_machine_that_has_never_run_does_the_first_one() {
        // Waiting for the disk to fill before ever running would make the first
        // experience of the tool the largest action it ever takes.
        let mut i = base(500 * GB);
        i.last_successful_run = None;
        assert_eq!(evaluate(&Config::default(), &i), None);
    }

    #[test]
    fn the_battery_gate_beats_the_overdue_override() {
        let mut i = base(500 * GB);
        i.last_successful_run = None;
        i.power = Power::Battery(5);
        assert!(matches!(
            evaluate(&Config::default(), &i),
            Some(Gated::LowBattery { .. })
        ));
    }

    #[test]
    fn thresholds_come_from_config() {
        let cfg = Config::parse(
            "[general]\nfree_space_floor = \"10GiB\"\n\n\
             [schedule]\nskip_on_battery_below = 50\n",
        )
        .unwrap();

        let mut i = base(50 * GB);
        i.last_successful_run = Some(Local::now());
        assert!(matches!(
            evaluate(&cfg, &i),
            Some(Gated::PlentyOfSpace { .. })
        ));

        let mut i = base(GB);
        i.power = Power::Battery(40);
        assert!(matches!(evaluate(&cfg, &i), Some(Gated::LowBattery { .. })));
    }

    #[test]
    fn pmset_output_parses_for_a_laptop_on_battery() {
        let sample = "Now drawing from 'Battery Power'\n \
                      -InternalBattery-0 (id=12345)\t87%; discharging; 4:32 remaining present: true\n";
        assert_eq!(parse_power(sample), Power::Battery(87));
    }

    #[test]
    fn pmset_output_parses_for_a_laptop_on_mains() {
        let sample = "Now drawing from 'AC Power'\n \
                      -InternalBattery-0 (id=12345)\t100%; charged; 0:00 remaining present: true\n";
        assert_eq!(parse_power(sample), Power::Ac);
    }

    #[test]
    fn pmset_output_parses_for_a_desktop_with_no_battery() {
        assert_eq!(parse_power("Now drawing from 'AC Power'\n"), Power::Ac);
    }

    #[test]
    fn unrecognised_pmset_output_is_unknown_not_a_guess() {
        assert_eq!(parse_power(""), Power::Unknown);
        assert_eq!(parse_power("something else entirely"), Power::Unknown);
    }

    #[test]
    fn on_battery_with_an_unreadable_percentage_errs_toward_not_running() {
        // Erring toward skipping is the cheap mistake; draining a laptop is not.
        assert_eq!(
            parse_power("Now drawing from 'Battery Power'\nno percentage here\n"),
            Power::Battery(0)
        );
    }

    #[test]
    fn every_gate_explains_itself() {
        for g in [
            Gated::PlentyOfSpace {
                free: 200 * GB,
                floor: 100 * GB,
            },
            Gated::LowBattery {
                percent: 10,
                threshold: 30,
            },
        ] {
            assert!(!g.describe().is_empty());
        }
    }
}
