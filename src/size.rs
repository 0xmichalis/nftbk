pub fn format_size(bytes: u64) -> (f64, &'static str) {
    const UNITS: [(&str, u64); 5] = [
        ("bytes", 1),
        ("KB", 1024),
        ("MB", 1024 * 1024),
        ("GB", 1024 * 1024 * 1024),
        ("TB", 1024 * 1024 * 1024 * 1024),
    ];

    for (unit, factor) in UNITS.iter().rev() {
        if bytes >= *factor {
            return (bytes as f64 / *factor as f64, unit);
        }
    }
    (bytes as f64, "bytes")
}

#[cfg(test)]
mod format_size_tests {
    use super::format_size;

    #[test]
    fn selects_largest_unit() {
        let (value, unit) = format_size(0);
        assert_eq!(value, 0.0);
        assert_eq!(unit, "bytes");

        let (value, unit) = format_size(1024 * 1024);
        assert_eq!(value, 1.0);
        assert_eq!(unit, "MB");

        let (value, unit) = format_size(3 * 1024 * 1024 * 1024 + 512);
        assert!(value > 3.0);
        assert_eq!(unit, "GB");
    }
}
