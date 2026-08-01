//! `sift install` and `sift uninstall` (FR-18, FR-21).

use crate::agent::{install, plist};
use crate::config::Config;
use crate::doctor;
use crate::report::human::size;
use crate::Result;

pub fn install_cmd(cfg: &Config, dry_run: bool, json: bool) -> Result<()> {
    if dry_run {
        return preview_cmd(cfg, json);
    }
    let done = install::install(cfg)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "label": plist::LABEL,
                "plist": done.plist_path.display().to_string(),
                "executable": done.exe.display().to_string(),
                "reinstalled": done.already_loaded,
                "schedule": format!("{:02}:{:02}", cfg.schedule.hour, cfg.schedule.minute),
            }))?
        );
        return Ok(());
    }

    if done.already_loaded {
        println!("sift — reinstalled the scheduled agent.");
    } else {
        println!("sift — scheduled agent installed.");
    }
    println!();
    println!(
        "  runs      daily at {:02}:{:02}",
        cfg.schedule.hour, cfg.schedule.minute
    );
    println!("  binary    {}", done.exe.display());
    println!("  plist     {}", done.plist_path.display());
    println!("  logs      {}", plist::stderr_log()?.display());
    println!();
    println!(
        "  It will skip a run when free space is above {} or the",
        size(cfg.general.free_space_floor.bytes())
    );
    println!(
        "  battery is below {}%, and quarantines rather than deletes.",
        cfg.schedule.skip_on_battery_below
    );
    println!();

    // The FDA instruction, at the moment it becomes load-bearing. Granting it
    // to Terminal is the mistake almost everyone makes, and the scheduled run
    // is exactly where that mistake stops being invisible.
    let caps = crate::caps::Capabilities::probe();
    println!("{}", doctor::fda_instructions(Some(&done.exe)));
    println!();
    if caps.fda.is_granted() {
        println!("  Your terminal currently has Full Disk Access. The agent does NOT");
        println!("  inherit that. Do the above for the binary itself, or the scheduled");
        println!("  run will quietly find less than this one does.");
    }
    println!();
    println!(
        "  Run now:   launchctl kickstart -k {}",
        plist::service_target()
    );
    println!("  Remove:    sift uninstall");

    Ok(())
}

/// `sift install --dry-run`: write nothing, load nothing.
fn preview_cmd(cfg: &Config, json: bool) -> Result<()> {
    let (plist_path, exe, xml) = install::preview(cfg)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "dry_run": true,
                "would_write": plist_path.display().to_string(),
                "would_run": format!(
                    "launchctl bootstrap {} {}",
                    plist::domain_target(),
                    plist_path.display()
                ),
                "executable": exe.display().to_string(),
                "plist": xml,
            }))?
        );
        return Ok(());
    }

    println!("sift — install --dry-run. Nothing has been written or loaded.");
    println!();
    if install::is_build_artifact(&exe) {
        println!(
            "  {}",
            install::build_artifact_warning(&exe).replace('\n', "\n  ")
        );
        println!();
    }
    println!("  would write  {}", plist_path.display());
    println!(
        "  would run    launchctl bootstrap {} {}",
        plist::domain_target(),
        plist_path.display()
    );
    println!();
    println!("  The job would persist across reboots until `sift uninstall`.");
    println!();
    for line in xml.lines() {
        println!("  {line}");
    }
    Ok(())
}

pub fn uninstall_cmd(json: bool) -> Result<()> {
    let done = install::uninstall()?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "was_loaded": done.was_loaded,
                "plist_removed": done.plist_removed,
                "bytes_purged": done.quarantine_purged,
                "config_removed": done.config_removed,
                "history_retained": done.history_path.as_ref().map(|p| p.display().to_string()),
            }))?
        );
        return Ok(());
    }

    if !done.was_loaded && !done.plist_removed {
        println!("sift — nothing was installed.");
    } else {
        println!("sift — scheduled agent removed.");
    }

    if done.quarantine_purged > 0 {
        println!(
            "  Permanently deleted {} of quarantined items.",
            size(done.quarantine_purged)
        );
    }
    if done.config_removed {
        println!("  Removed your configuration.");
    }

    // FR-21: name it, do not delete it. This is the user's record of what was
    // removed from their machine, and destroying it as a side effect of
    // uninstalling would be indefensible.
    match &done.history_path {
        Some(p) => {
            println!();
            println!("  Your run history was kept, because it is the only record of what");
            println!("  sift ever deleted. Remove it yourself if you want it gone:");
            println!();
            println!("    rm {}", p.display());
        }
        None => println!("  Nothing left behind."),
    }

    Ok(())
}
