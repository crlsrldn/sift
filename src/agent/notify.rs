//! Local notifications for scheduled runs (PRD §7).
//!
//! `osascript display notification`, not `UNUserNotificationCenter` — the
//! latter needs a signed app bundle and is deferred to a v2 menu-bar client.
//!
//! # Escaping is a safety property here, not a formatting nicety
//!
//! Notification text interpolates scanner labels, and labels derive from
//! filesystem paths. A directory named `"; do shell script "…` is a path a user
//! can create, deliberately or by accident. AppleScript string escaping is the
//! only thing between that and `osascript` executing it.

use crate::report::human::size;
use std::time::Duration;

/// Escape a string for an AppleScript double-quoted literal.
///
/// Backslash first — escaping quotes before backslashes would double-escape the
/// backslashes that the quote escaping introduced.
pub fn escape_applescript(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            // Control characters are dropped rather than escaped. They have no
            // place in a notification and are the most likely vehicle for
            // something surprising.
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Build the notification body from what was reclaimed.
///
/// Names the sources rather than only the total (Principle 6): "Freed 34 GB"
/// is worthless; "Freed 34 GB — Xcode DeviceSupport, Rust targets" is the
/// product.
pub fn body(bytes: u64, sources: &[&str]) -> String {
    let named: Vec<&str> = sources.iter().take(3).copied().collect();
    if named.is_empty() {
        format!("Freed {}", size(bytes))
    } else {
        format!("Freed {} — {}", size(bytes), named.join(", "))
    }
}

/// Post a notification if the run cleared the configured threshold.
///
/// Returns whether one was sent. A failure to notify is never a failure of the
/// run: the disk space was reclaimed either way.
pub fn maybe_notify(bytes: u64, threshold: u64, sources: &[&str]) -> bool {
    if bytes < threshold || threshold == 0 {
        return false;
    }
    send("sift", &body(bytes, sources))
}

pub fn send(title: &str, message: &str) -> bool {
    let script = format!(
        "display notification \"{}\" with title \"{}\"",
        escape_applescript(message),
        escape_applescript(title)
    );

    matches!(
        crate::action::delegate::probe("osascript", &["-e", &script], Duration::from_secs(15)),
        crate::action::delegate::Outcome::Ok { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_and_backslashes_are_escaped() {
        assert_eq!(escape_applescript(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_applescript(r"a\b"), r"a\\b");
    }

    #[test]
    fn backslashes_are_escaped_before_quotes() {
        // Escaping quotes first would double-escape the backslashes that the
        // quote escaping itself introduces.
        assert_eq!(escape_applescript(r#"\""#), r#"\\\""#);
    }

    #[test]
    fn an_injection_attempt_in_a_path_cannot_close_the_string() {
        // Labels derive from filesystem paths, and this is a directory name a
        // user can create.
        let hostile = r#"x"; do shell script "rm -rf ~"; display notification ""#;
        let escaped = escape_applescript(hostile);

        // Every quote in the output is preceded by a backslash, so none of them
        // terminate the AppleScript literal.
        let chars: Vec<char> = escaped.chars().collect();
        for (i, c) in chars.iter().enumerate() {
            if *c == '"' {
                assert!(
                    i > 0 && chars[i - 1] == '\\',
                    "an unescaped quote at {i} would close the string: {escaped}"
                );
            }
        }
    }

    #[test]
    fn control_characters_are_dropped() {
        assert_eq!(escape_applescript("a\nb\tc\0d"), "abcd");
    }

    #[test]
    fn the_body_names_sources_not_just_a_total() {
        // Principle 6. "Freed 34 GB" is worthless; the named sources are the
        // product.
        let b = body(34_000_000_000, &["Xcode DeviceSupport", "Rust targets"]);
        assert!(b.contains("34.0 GB"), "{b}");
        assert!(b.contains("Xcode DeviceSupport"), "{b}");
        assert!(b.contains("Rust targets"), "{b}");
    }

    #[test]
    fn the_body_caps_the_source_list() {
        // A notification listing twelve scanners is unreadable.
        let many = ["a", "b", "c", "d", "e", "f"];
        let b = body(1_000_000_000, &many);
        assert!(!b.contains('f'), "{b}");
    }

    #[test]
    fn a_total_with_no_sources_still_reads_sensibly() {
        assert_eq!(body(1_000_000_000, &[]), "Freed 1.0 GB");
    }

    #[test]
    fn a_run_below_the_threshold_does_not_notify() {
        assert!(!maybe_notify(500_000_000, 1_073_741_824, &["x"]));
    }

    #[test]
    fn a_zero_threshold_disables_notifications_entirely() {
        // Rather than notifying on every run, which would be the literal
        // reading and is obviously not what someone setting 0 wants.
        assert!(!maybe_notify(u64::MAX, 0, &["x"]));
    }
}
