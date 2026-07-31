//! Human-writable byte sizes for config (`"100GiB"`, `"1GB"`, `1024`).

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A byte count parsed from a human-readable string.
///
/// Both SI (`GB` = 1000³) and binary (`GiB` = 1024³) units are supported and
/// mean different things, because silently treating `GB` as `GiB` would make
/// the circuit breaker's limit 7% larger than what the user wrote (FR-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    pub const fn bytes(self) -> u64 {
        self.0
    }

    pub const fn gib(n: u64) -> Self {
        Self(n * 1024 * 1024 * 1024)
    }
}

const UNITS: &[(&str, u64)] = &[
    // Longest first: `kib` must be tried before `kb`, and both before `b`,
    // otherwise a suffix match would truncate the unit and misread the value.
    ("tib", 1024 * 1024 * 1024 * 1024),
    ("gib", 1024 * 1024 * 1024),
    ("mib", 1024 * 1024),
    ("kib", 1024),
    ("tb", 1_000_000_000_000),
    ("gb", 1_000_000_000),
    ("mb", 1_000_000),
    ("kb", 1_000),
    ("b", 1),
];

impl std::str::FromStr for ByteSize {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if t.is_empty() {
            return Err("empty byte size".into());
        }

        // A bare number is bytes.
        if let Ok(n) = t.parse::<u64>() {
            return Ok(ByteSize(n));
        }

        let lower = t.to_ascii_lowercase();
        for (suffix, mult) in UNITS {
            if let Some(num) = lower.strip_suffix(suffix) {
                let num = num.trim();
                if num.is_empty() {
                    return Err(format!("`{t}` has a unit but no number"));
                }

                // Reject internal whitespace: "100 GiB" is fine, "1 0 0GiB" is not.
                if num.split_whitespace().count() != 1 {
                    return Err(format!("`{t}` is not a valid byte size"));
                }
                let num = num.trim();

                let value: f64 = num
                    .parse()
                    .map_err(|_| format!("`{num}` in `{t}` is not a number"))?;
                if !value.is_finite() || value < 0.0 {
                    return Err(format!("`{t}` is not a valid byte size"));
                }

                let bytes = value * (*mult as f64);
                if bytes > u64::MAX as f64 {
                    return Err(format!("`{t}` overflows a 64-bit byte count"));
                }
                return Ok(ByteSize(bytes as u64));
            }
        }

        Err(format!(
            "`{t}` is not a valid byte size; expected a number optionally followed by \
             B, KB, KiB, MB, MiB, GB, GiB, TB, or TiB (e.g. `100GiB`)"
        ))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", humansize::format_size(self.0, humansize::BINARY))
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl de::Visitor<'_> for V {
            type Value = ByteSize;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a byte size such as `100GiB`, `1GB`, or a plain integer")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<ByteSize, E> {
                v.parse().map_err(de::Error::custom)
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<ByteSize, E> {
                Ok(ByteSize(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<ByteSize, E> {
                u64::try_from(v)
                    .map(ByteSize)
                    .map_err(|_| de::Error::custom(format!("byte size cannot be negative: {v}")))
            }
        }

        d.deserialize_any(V)
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_binary_and_si_units_as_different_values() {
        // Conflating these would silently inflate the circuit-breaker limit by 7%.
        assert_eq!("1GiB".parse::<ByteSize>().unwrap().bytes(), 1_073_741_824);
        assert_eq!("1GB".parse::<ByteSize>().unwrap().bytes(), 1_000_000_000);
        assert_ne!(
            "1GiB".parse::<ByteSize>().unwrap(),
            "1GB".parse::<ByteSize>().unwrap()
        );
    }

    #[test]
    fn parses_the_spec_defaults() {
        assert_eq!("100GiB".parse::<ByteSize>().unwrap(), ByteSize::gib(100));
        assert_eq!("1GiB".parse::<ByteSize>().unwrap(), ByteSize::gib(1));
    }

    #[test]
    fn bare_integer_is_bytes() {
        assert_eq!("1024".parse::<ByteSize>().unwrap().bytes(), 1024);
        assert_eq!("0".parse::<ByteSize>().unwrap().bytes(), 0);
    }

    #[test]
    fn case_and_surrounding_space_are_tolerated() {
        assert_eq!("100gib".parse::<ByteSize>().unwrap(), ByteSize::gib(100));
        assert_eq!("100 GiB".parse::<ByteSize>().unwrap(), ByteSize::gib(100));
        assert_eq!(
            "  100GIB  ".parse::<ByteSize>().unwrap(),
            ByteSize::gib(100)
        );
    }

    #[test]
    fn fractional_values_work() {
        assert_eq!("1.5GiB".parse::<ByteSize>().unwrap().bytes(), 1_610_612_736);
        assert_eq!("0.5KiB".parse::<ByteSize>().unwrap().bytes(), 512);
    }

    #[test]
    fn longest_unit_wins_so_kib_is_not_read_as_b() {
        assert_eq!("1KiB".parse::<ByteSize>().unwrap().bytes(), 1024);
        assert_eq!("1B".parse::<ByteSize>().unwrap().bytes(), 1);
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["100 gigs", "", "GiB", "abc", "-5GiB", "1.2.3GiB", "∞GiB"] {
            assert!(
                bad.parse::<ByteSize>().is_err(),
                "`{bad}` should not parse as a byte size"
            );
        }
    }

    #[test]
    fn error_message_shows_accepted_units() {
        let e = "100 gigs".parse::<ByteSize>().unwrap_err();
        assert!(e.contains("GiB"), "unhelpful error: {e}");
    }

    #[test]
    fn deserializes_from_string_and_integer() {
        #[derive(Deserialize)]
        struct T {
            v: ByteSize,
        }

        let a: T = toml::from_str(r#"v = "100GiB""#).unwrap();
        assert_eq!(a.v, ByteSize::gib(100));

        let b: T = toml::from_str("v = 4096").unwrap();
        assert_eq!(b.v.bytes(), 4096);
    }

    #[test]
    fn deserialize_rejects_negative() {
        #[derive(Deserialize)]
        struct T {
            #[allow(dead_code)]
            v: ByteSize,
        }
        assert!(toml::from_str::<T>("v = -1").is_err());
    }
}
