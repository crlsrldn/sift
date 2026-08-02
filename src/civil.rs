// Days-since-epoch to a calendar date.
//
// `//` and not `//!`: this file is `include!`d by build.rs, and an inner doc
// comment is only legal at the top of a file. The module documentation lives
// on the `pub mod civil;` declaration in lib.rs instead.

/// Days since 1970-01-01 to `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`: exact over the whole range, no lookup
/// table, and shifts the year to start in March so the leap day lands at the
/// end of the era and needs no special case.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_itself() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn known_dates_round_trip() {
        // Spot values computed independently.
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        assert_eq!(civil_from_days(365), (1971, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(20_635), (2026, 7, 1));
    }

    #[test]
    fn leap_days_are_real_days() {
        // The case the March-based year shift exists to handle. 2000 is a leap
        // year (divisible by 400) and 1900 is not (divisible by 100) — a naive
        // implementation gets one of the two wrong.
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));

        // 1900 is divisible by 100 but not 400, so February has 28 days and
        // these two are consecutive — there is no day in between.
        assert_eq!(civil_from_days(-25_509), (1900, 2, 28));
        assert_eq!(civil_from_days(-25_508), (1900, 3, 1));
    }

    #[test]
    fn dates_before_the_epoch_do_not_wrap() {
        // `days` comes from a division that can go negative if a clock is
        // wrong or SOURCE_DATE_EPOCH is set oddly. Truncating division toward
        // zero would put this in the wrong era.
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(-365), (1969, 1, 1));
    }

    #[test]
    fn every_day_across_a_leap_cycle_is_consecutive_and_valid() {
        // Walks 1996-01-01 through 2036, checking the sequence never skips,
        // repeats, or produces an impossible date. Catches era-boundary and
        // month-length errors that spot checks would step over.
        let start = 9_496; // 1996-01-01
        let mut prev = civil_from_days(start);
        assert_eq!(prev, (1996, 1, 1));

        for offset in 1..=14_610 {
            let (y, m, d) = civil_from_days(start + offset);
            assert!((1..=12).contains(&m), "bad month {m} at +{offset}");
            assert!((1..=31).contains(&d), "bad day {d} at +{offset}");

            let (py, pm, pd) = prev;
            let consecutive = (y, m, d) == (py, pm, pd + 1)
                || (d == 1 && m == pm + 1 && y == py)
                || (d == 1 && m == 1 && y == py + 1);
            assert!(
                consecutive,
                "{py}-{pm}-{pd} was followed by {y}-{m}-{d} at +{offset}"
            );
            prev = (y, m, d);
        }
    }
}
