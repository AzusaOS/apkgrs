//! UTC timestamp formatting without a date library.

/// Convert days since 1970-01-01 to a civil (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // Howard Hinnant's algorithm.
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn parts(unix: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, secs / 3600, (secs / 60) % 60, secs % 60)
}

/// `YYYYMMDDhhmmss` in UTC — the version stamp format of the databases.
pub fn stamp(unix: i64) -> String {
    let (y, m, d, h, mi, s) = parts(unix);
    format!("{y:04}{m:02}{d:02}{h:02}{mi:02}{s:02}")
}

/// `YYYY-MM-DD hh:mm:ss UTC` for logs.
pub fn human(unix: i64) -> String {
    let (y, m, d, h, mi, s) = parts(unix);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

/// Current unix time in seconds.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps() {
        assert_eq!(stamp(0), "19700101000000");
        assert_eq!(stamp(1_670_103_606), "20221203214006");
        assert_eq!(stamp(951_782_400), "20000229000000");
        assert_eq!(human(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }
}
