//! Timestamps: Ion text parsing and printing, `TO_STRING` patterns, and
//! the date parts of `EXTRACT`, `DATE_ADD` and `DATE_DIFF`.
//!
//! A timestamp keeps the precision it was written with, as Ion does:
//! `TO_TIMESTAMP('2007T')` prints back as `2007T`.

use super::error::{SelectError, SelectResult};
use chrono::{DateTime, Datelike, Duration, FixedOffset, Months, NaiveDate, TimeZone, Timelike};

/// How much of a timestamp was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Precision {
    Year,
    Month,
    Day,
    Minute,
    Second,
    /// Seconds with this many fractional digits (1..=9).
    Fraction(u8),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ts {
    pub dt: DateTime<FixedOffset>,
    pub precision: Precision,
}

/// The parts `EXTRACT`, `DATE_ADD` and `DATE_DIFF` name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatePart {
    Year,
    Month,
    Day,
    Hour,
    Minute,
    Second,
    TimezoneHour,
    TimezoneMinute,
}

impl DatePart {
    pub fn parse(word: &str) -> Option<Self> {
        Some(match word.to_ascii_lowercase().as_str() {
            "year" => Self::Year,
            "month" => Self::Month,
            "day" => Self::Day,
            "hour" => Self::Hour,
            "minute" => Self::Minute,
            "second" => Self::Second,
            "timezone_hour" => Self::TimezoneHour,
            "timezone_minute" => Self::TimezoneMinute,
            _ => return None,
        })
    }
}

fn bad_ts(s: &str) -> SelectError {
    SelectError::new(
        "CastFailed",
        format!("'{s}' is not a timestamp (expected an ISO 8601 / Ion timestamp)"),
    )
}

fn digits(s: &[u8], at: usize, n: usize) -> Option<u32> {
    let part = s.get(at..at + n)?;
    if !part.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(part).ok()?.parse().ok()
}

/// Parse an Ion / ISO 8601 timestamp: `2007T`, `2007-02T`, `2007-02-23`,
/// `2007-02-23T12:14Z`, `2007-02-23T12:14:33.079-08:00`, and the basic
/// form `20070223T121433Z`. A time without an offset is taken as UTC.
pub fn parse_timestamp(input: &str) -> SelectResult<Ts> {
    let s = input.trim().as_bytes();
    let err = || bad_ts(input);
    let year = digits(s, 0, 4).ok_or_else(err)? as i32;
    let utc = FixedOffset::east_opt(0).unwrap();
    let date = |y: i32, m: u32, d: u32| NaiveDate::from_ymd_opt(y, m, d).ok_or_else(err);
    let at_midnight = |d: NaiveDate, precision| -> SelectResult<Ts> {
        let dt = utc
            .from_local_datetime(&d.and_hms_opt(0, 0, 0).unwrap())
            .single()
            .ok_or_else(err)?;
        Ok(Ts { dt, precision })
    };
    // Year only: `2007T` (or a bare `2007`).
    if s.len() == 4 || (s.len() == 5 && s[4] == b'T') {
        return at_midnight(date(year, 1, 1)?, Precision::Year);
    }
    let (month, day, mut i, basic) = if s.get(4) == Some(&b'-') {
        let month = digits(s, 5, 2).ok_or_else(err)?;
        if s.len() == 7 || (s.len() == 8 && s[7] == b'T') {
            return at_midnight(date(year, month, 1)?, Precision::Month);
        }
        if s.get(7) != Some(&b'-') {
            return Err(err());
        }
        (month, digits(s, 8, 2).ok_or_else(err)?, 10, false)
    } else {
        // Basic form: YYYYMMDD[Thhmm[ss[.f]]][Z|±hhmm]
        (
            digits(s, 4, 2).ok_or_else(err)?,
            digits(s, 6, 2).ok_or_else(err)?,
            8,
            true,
        )
    };
    let day_date = date(year, month, day)?;
    if i == s.len() || (i + 1 == s.len() && s[i] == b'T') {
        return at_midnight(day_date, Precision::Day);
    }
    if s[i] != b'T' && s[i] != b't' && s[i] != b' ' {
        return Err(err());
    }
    i += 1;
    let hour = digits(s, i, 2).ok_or_else(err)?;
    i += 2;
    if !basic {
        if s.get(i) != Some(&b':') {
            return Err(err());
        }
        i += 1;
    }
    let minute = digits(s, i, 2).ok_or_else(err)?;
    i += 2;
    let mut second = 0;
    let mut nanos = 0u32;
    let mut precision = Precision::Minute;
    let has_seconds = if basic {
        s.get(i).is_some_and(u8::is_ascii_digit)
    } else {
        s.get(i) == Some(&b':')
    };
    if has_seconds {
        if !basic {
            i += 1;
        }
        second = digits(s, i, 2).ok_or_else(err)?;
        i += 2;
        precision = Precision::Second;
        if s.get(i) == Some(&b'.') {
            i += 1;
            let start = i;
            while s.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            let n = i - start;
            if n == 0 {
                return Err(err());
            }
            let kept = n.min(9);
            let frac: u32 = std::str::from_utf8(&s[start..start + kept])
                .unwrap()
                .parse()
                .map_err(|_| err())?;
            nanos = frac * 10u32.pow((9 - kept) as u32);
            precision = Precision::Fraction(kept as u8);
        }
    }
    let offset_secs = match s.get(i) {
        None => 0,
        Some(b'Z' | b'z') if i + 1 == s.len() => 0,
        Some(&sign @ (b'+' | b'-')) => {
            let oh = digits(s, i + 1, 2).ok_or_else(err)? as i32;
            let mut j = i + 3;
            let om = if j == s.len() {
                0
            } else {
                if s[j] == b':' {
                    j += 1;
                }
                let m = digits(s, j, 2).ok_or_else(err)? as i32;
                j += 2;
                m
            };
            if j != s.len() {
                return Err(err());
            }
            let total = oh * 3600 + om * 60;
            if sign == b'-' { -total } else { total }
        }
        _ => return Err(err()),
    };
    let offset = FixedOffset::east_opt(offset_secs).ok_or_else(err)?;
    let naive = day_date
        .and_hms_nano_opt(hour, minute, second, nanos)
        .ok_or_else(err)?;
    let dt = offset
        .from_local_datetime(&naive)
        .single()
        .ok_or_else(err)?;
    Ok(Ts { dt, precision })
}

fn offset_text(secs: i32) -> String {
    if secs == 0 {
        return "Z".to_string();
    }
    let sign = if secs < 0 { '-' } else { '+' };
    let a = secs.abs();
    format!("{sign}{:02}:{:02}", a / 3600, (a % 3600) / 60)
}

/// Ion text of a timestamp, at its own precision.
pub fn format_timestamp(ts: &Ts) -> String {
    let d = &ts.dt;
    let off = offset_text(d.offset().local_minus_utc());
    match ts.precision {
        Precision::Year => format!("{:04}T", d.year()),
        Precision::Month => format!("{:04}-{:02}T", d.year(), d.month()),
        Precision::Day => format!("{:04}-{:02}-{:02}", d.year(), d.month(), d.day()),
        Precision::Minute => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}{off}",
            d.year(),
            d.month(),
            d.day(),
            d.hour(),
            d.minute()
        ),
        Precision::Second => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{off}",
            d.year(),
            d.month(),
            d.day(),
            d.hour(),
            d.minute(),
            d.second()
        ),
        Precision::Fraction(n) => {
            let frac = format!("{:09}", d.nanosecond());
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{}{off}",
                d.year(),
                d.month(),
                d.day(),
                d.hour(),
                d.minute(),
                d.second(),
                &frac[..n as usize]
            )
        }
    }
}

/// `EXTRACT(part FROM ts)`.
pub fn extract(part: DatePart, ts: &Ts) -> i64 {
    let d = &ts.dt;
    let off = d.offset().local_minus_utc();
    match part {
        DatePart::Year => i64::from(d.year()),
        DatePart::Month => i64::from(d.month()),
        DatePart::Day => i64::from(d.day()),
        DatePart::Hour => i64::from(d.hour()),
        DatePart::Minute => i64::from(d.minute()),
        DatePart::Second => i64::from(d.second()),
        DatePart::TimezoneHour => i64::from(off / 3600),
        DatePart::TimezoneMinute => i64::from((off % 3600) / 60),
    }
}

fn overflow() -> SelectError {
    SelectError::new("IntegerOverflow", "the date is out of range")
}

/// `DATE_ADD(part, n, ts)`.
pub fn date_add(part: DatePart, n: i64, ts: &Ts) -> SelectResult<Ts> {
    let d = ts.dt;
    let months = |m: i64| -> SelectResult<DateTime<FixedOffset>> {
        let mag = Months::new(u32::try_from(m.unsigned_abs()).map_err(|_| overflow())?);
        if m >= 0 {
            d.checked_add_months(mag)
        } else {
            d.checked_sub_months(mag)
        }
        .ok_or_else(overflow)
    };
    let plus = |dur: Option<Duration>| {
        dur.and_then(|x| d.checked_add_signed(x))
            .ok_or_else(overflow)
    };
    let (dt, at_least) = match part {
        DatePart::Year => (
            months(n.checked_mul(12).ok_or_else(overflow)?)?,
            Precision::Year,
        ),
        DatePart::Month => (months(n)?, Precision::Month),
        DatePart::Day => (plus(Duration::try_days(n))?, Precision::Day),
        DatePart::Hour => (plus(Duration::try_hours(n))?, Precision::Minute),
        DatePart::Minute => (plus(Duration::try_minutes(n))?, Precision::Minute),
        DatePart::Second => (plus(Duration::try_seconds(n))?, Precision::Second),
        DatePart::TimezoneHour | DatePart::TimezoneMinute => {
            return Err(SelectError::new(
                "IllegalSqlFunctionArgument",
                "DATE_ADD takes year, month, day, hour, minute or second",
            ));
        }
    };
    Ok(Ts {
        dt,
        precision: ts.precision.max(at_least),
    })
}

/// `DATE_DIFF(part, a, b)`: whole `part`s from `a` to `b` (negative when `b`
/// is earlier). Years and months count calendar months completed.
pub fn date_diff(part: DatePart, a: &Ts, b: &Ts) -> SelectResult<i64> {
    let (x, y) = (a.dt, b.dt.with_timezone(a.dt.offset()));
    let secs = y.signed_duration_since(x);
    Ok(match part {
        DatePart::Year | DatePart::Month => {
            let mut months =
                i64::from(y.year() - x.year()) * 12 + i64::from(y.month()) - i64::from(x.month());
            // Not a whole month until b's day-and-time reaches a's.
            let rest = |t: &DateTime<FixedOffset>| {
                (t.day(), t.hour(), t.minute(), t.second(), t.nanosecond())
            };
            if months > 0 && rest(&y) < rest(&x) {
                months -= 1;
            } else if months < 0 && rest(&y) > rest(&x) {
                months += 1;
            }
            if part == DatePart::Year {
                months / 12
            } else {
                months
            }
        }
        DatePart::Day => secs.num_days(),
        DatePart::Hour => secs.num_hours(),
        DatePart::Minute => secs.num_minutes(),
        DatePart::Second => secs.num_seconds(),
        DatePart::TimezoneHour | DatePart::TimezoneMinute => {
            return Err(SelectError::new(
                "IllegalSqlFunctionArgument",
                "DATE_DIFF takes year, month, day, hour, minute or second",
            ));
        }
    })
}

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

fn offset_pattern(secs: i32, letter: char, n: usize) -> String {
    if letter == 'X' && secs == 0 {
        return "Z".to_string();
    }
    let sign = if secs < 0 { '-' } else { '+' };
    let a = secs.abs();
    let (h, m) = (a / 3600, (a % 3600) / 60);
    match n {
        1 if m == 0 => format!("{sign}{h:02}"),
        1 | 2 | 4 => format!("{sign}{h:02}{m:02}"),
        _ => format!("{sign}{h:02}:{m:02}"),
    }
}

/// `TO_STRING(ts, pattern)`, with AWS's pattern letters (y M d a h H m s S n
/// X x); text in single quotes and any other character are copied.
pub fn to_string(ts: &Ts, pattern: &str) -> SelectResult<String> {
    let d = &ts.dt;
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '\'' {
                out.push(chars[j]);
                j += 1;
            }
            if j == chars.len() {
                return Err(SelectError::new(
                    "EvaluatorUnterminatedTimestampFormatPatternToken",
                    "an unterminated quoted text in the TO_STRING pattern",
                ));
            }
            i = j + 1;
            continue;
        }
        if !c.is_ascii_alphabetic() {
            out.push(c);
            i += 1;
            continue;
        }
        let mut n = 1;
        while i + n < chars.len() && chars[i + n] == c {
            n += 1;
        }
        i += n;
        let hour12 = match d.hour() % 12 {
            0 => 12,
            h => h,
        };
        let piece = match (c, n) {
            ('y', 2) => format!("{:02}", d.year().rem_euclid(100)),
            ('y', 1 | 3) => d.year().to_string(),
            ('y', _) => format!("{:0width$}", d.year(), width = n),
            ('M', 1) => d.month().to_string(),
            ('M', 2) => format!("{:02}", d.month()),
            ('M', 3) => MONTHS[d.month0() as usize][..3].to_string(),
            ('M', 4) => MONTHS[d.month0() as usize].to_string(),
            ('M', 5) => MONTHS[d.month0() as usize][..1].to_string(),
            ('d', 1) => d.day().to_string(),
            ('d', 2) => format!("{:02}", d.day()),
            ('a', 1) => (if d.hour() < 12 { "AM" } else { "PM" }).to_string(),
            ('h', 1) => hour12.to_string(),
            ('h', 2) => format!("{hour12:02}"),
            ('H', 1) => d.hour().to_string(),
            ('H', 2) => format!("{:02}", d.hour()),
            ('m', 1) => d.minute().to_string(),
            ('m', 2) => format!("{:02}", d.minute()),
            ('s', 1) => d.second().to_string(),
            ('s', 2) => format!("{:02}", d.second()),
            ('S', 1..=9) => format!("{:09}", d.nanosecond())[..n].to_string(),
            ('n', 1) => d.nanosecond().to_string(),
            ('X' | 'x', 1..=5) => offset_pattern(d.offset().local_minus_utc(), c, n),
            _ => {
                return Err(SelectError::new(
                    "EvaluatorInvalidTimestampFormatPatternSymbol",
                    format!(
                        "'{}' is not a TO_STRING pattern symbol",
                        c.to_string().repeat(n)
                    ),
                ));
            }
        };
        out.push_str(&piece);
    }
    Ok(out)
}

/// The statement's `UTCNOW()`, at millisecond precision.
pub fn now() -> Ts {
    let utc = FixedOffset::east_opt(0).unwrap();
    let now = chrono::Utc::now();
    let ms = now.timestamp_millis();
    Ts {
        dt: utc
            .timestamp_millis_opt(ms)
            .single()
            .unwrap_or_else(|| now.with_timezone(&utc)),
        precision: Precision::Fraction(3),
    }
}

/// A timestamp at `secs` + `nanos` after the epoch, UTC.
pub fn from_epoch(secs: i64, nanos: u32, precision: Precision) -> Option<Ts> {
    let utc = FixedOffset::east_opt(0).unwrap();
    let dt = utc.timestamp_opt(secs, nanos).single()?;
    Some(Ts { dt, precision })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Ts {
        parse_timestamp(s).unwrap()
    }

    #[test]
    fn ion_timestamps_print_back_at_their_precision() {
        for s in [
            "2007T",
            "2007-02T",
            "2007-02-23",
            "2007-02-23T12:14Z",
            "2007-02-23T12:14:33Z",
            "2007-02-23T12:14:33.079-08:00",
            "2007-02-23T12:14:33.5+05:30",
        ] {
            assert_eq!(format_timestamp(&ts(s)), s);
        }
    }

    #[test]
    fn the_basic_form_parses_too() {
        let t = ts("19501231T235959Z");
        assert_eq!(format_timestamp(&t), "1950-12-31T23:59:59Z");
        assert_eq!(extract(DatePart::Year, &t), 1950);
        assert_eq!(extract(DatePart::Month, &t), 12);
    }

    #[test]
    fn garbage_is_not_a_timestamp() {
        for s in [
            "",
            "20",
            "2007-13-01",
            "2007-02-30",
            "abcdT",
            "2007-02-23T25:00Z",
        ] {
            assert_eq!(parse_timestamp(s).unwrap_err().code, "CastFailed", "{s}");
        }
    }

    #[test]
    fn extract_reads_each_part() {
        let t = ts("2007-02-23T12:14:33.079-08:30");
        assert_eq!(extract(DatePart::Day, &t), 23);
        assert_eq!(extract(DatePart::Hour, &t), 12);
        assert_eq!(extract(DatePart::Minute, &t), 14);
        assert_eq!(extract(DatePart::Second, &t), 33);
        assert_eq!(extract(DatePart::TimezoneHour, &t), -8);
        assert_eq!(extract(DatePart::TimezoneMinute, &t), -30);
    }

    #[test]
    fn date_add_and_date_diff_agree() {
        let t = ts("2020-01-31T10:00:00Z");
        let plus = date_add(DatePart::Month, 1, &t).unwrap();
        assert_eq!(format_timestamp(&plus), "2020-02-29T10:00:00Z");
        assert_eq!(date_diff(DatePart::Month, &t, &plus).unwrap(), 0);
        let two = date_add(DatePart::Month, 2, &t).unwrap();
        assert_eq!(date_diff(DatePart::Month, &t, &two).unwrap(), 2);
        // Dec 31 + 2 months is Feb 29: one whole month and a bit.
        let dec = ts("2019-12-31T10:00:00Z");
        let feb = date_add(DatePart::Month, 2, &dec).unwrap();
        assert_eq!(date_diff(DatePart::Month, &dec, &feb).unwrap(), 1);
        let a = ts("1952-02-28T00:00:00Z");
        let b = date_add(DatePart::Day, 366, &a).unwrap();
        assert_eq!(date_diff(DatePart::Year, &a, &b).unwrap(), 1);
        let day = date_add(DatePart::Day, 1, &t).unwrap();
        assert_eq!(date_diff(DatePart::Hour, &t, &day).unwrap(), 24);
        assert_eq!(date_diff(DatePart::Hour, &day, &t).unwrap(), -24);
        let m = ts("2007-03-15T00:00:00Z");
        let earlier = ts("2007-01-20T00:00:00Z");
        assert_eq!(date_diff(DatePart::Month, &m, &earlier).unwrap(), -1);
    }

    #[test]
    fn date_add_raises_a_day_precision_to_minutes_for_hours() {
        let t = ts("2007-02-23");
        let later = date_add(DatePart::Hour, 5, &t).unwrap();
        assert_eq!(format_timestamp(&later), "2007-02-23T05:00Z");
    }

    #[test]
    fn to_string_follows_the_aws_pattern_letters() {
        let t = ts("1969-07-20T20:18:04.123456789-07:00");
        let f = |p: &str| to_string(&t, p).unwrap();
        assert_eq!(f("MMMM d, y"), "July 20, 1969");
        assert_eq!(f("MMM d, yyyy h:m a"), "Jul 20, 1969 8:18 PM");
        assert_eq!(f("y-MM-dd'T'H:m:ssX"), "1969-07-20T20:18:04-07");
        assert_eq!(f("yy"), "69");
        assert_eq!(f("SSS"), "123");
        assert_eq!(f("n"), "123456789");
        assert_eq!(f("XXX"), "-07:00");
        assert_eq!(f("xx"), "-0700");
        let utc = ts("2001-01-01T00:00:00Z");
        assert_eq!(to_string(&utc, "X").unwrap(), "Z");
        assert_eq!(to_string(&utc, "x").unwrap(), "+00");
        assert_eq!(
            to_string(&t, "q").unwrap_err().code,
            "EvaluatorInvalidTimestampFormatPatternSymbol"
        );
    }
}
