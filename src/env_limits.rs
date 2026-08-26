//! Canonical parsing for positive-integer environment limits.
//!
//! Spec: `runtime-resource-bounds.spec.md` RRB-C1. A limit value accepts only
//! positive base-10 integers after trimming ASCII whitespace; missing, zero,
//! invalid, or overflowing values fall back to the documented default.

/// Parses `raw` as a positive integer, falling back to `default` for missing,
/// empty, zero, negative, non-numeric, or overflowing values (RRB-C1).
pub fn parse_positive<T>(raw: Option<&str>, default: T) -> T
where
    T: std::str::FromStr + PartialOrd + From<u8> + Copy,
{
    raw.and_then(|value| value.trim().parse::<T>().ok())
        .filter(|value| *value > T::from(0))
        .unwrap_or(default)
}

/// Reads the environment variable `name` and parses it with [`parse_positive`].
pub fn positive<T>(name: &str, default: T) -> T
where
    T: std::str::FromStr + PartialOrd + From<u8> + Copy,
{
    parse_positive(std::env::var(name).ok().as_deref(), default)
}

#[cfg(test)]
mod tests {
    use super::parse_positive;

    #[test]
    fn accepts_positive_integers_and_trims_whitespace() {
        assert_eq!(parse_positive(Some("17"), 9usize), 17);
        assert_eq!(parse_positive(Some(" 3 "), 9usize), 3);
        assert_eq!(parse_positive(Some("42"), 9u64), 42);
    }

    #[test]
    fn falls_back_to_default_for_missing_zero_invalid_or_overflow() {
        assert_eq!(parse_positive(None, 9usize), 9);
        assert_eq!(parse_positive(Some(""), 9usize), 9);
        assert_eq!(parse_positive(Some("0"), 9usize), 9);
        assert_eq!(parse_positive(Some("-1"), 9usize), 9);
        assert_eq!(parse_positive(Some("invalid"), 9usize), 9);
        assert_eq!(parse_positive(Some("18446744073709551616"), 9u64), 9);
    }
}
