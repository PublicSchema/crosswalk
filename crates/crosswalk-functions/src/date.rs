use crate::FunctionError;
use chrono::{Datelike, Duration, NaiveDate, NaiveDateTime, TimeZone};
use chrono_tz::Tz;
use std::str::FromStr;

pub fn icuish_to_chrono(pattern: &str) -> String {
    pattern
        .replace("XXX", "%:z")
        .replace("yyyy", "%Y")
        .replace("MM", "%m")
        .replace("dd", "%d")
        .replace("HH", "%H")
        .replace("mm", "%M")
        .replace("ss", "%S")
}

pub fn parse_date(input: &str, pattern: Option<&str>) -> Result<String, FunctionError> {
    let chrono_pattern = icuish_to_chrono(pattern.unwrap_or("yyyy-MM-dd"));
    let date = NaiveDate::parse_from_str(input, &chrono_pattern)
        .map_err(|err| FunctionError::new("DATE_PARSE", err.to_string()))?;
    Ok(date.format("%Y-%m-%d").to_string())
}

pub fn parse_datetime(
    input: &str,
    pattern: Option<&str>,
    timezone_hint: Option<&str>,
) -> Result<String, FunctionError> {
    if let Some(pattern) = pattern {
        let chrono_pattern = icuish_to_chrono(pattern);
        if let Ok(dt) = chrono::DateTime::parse_from_str(input, &chrono_pattern) {
            return Ok(dt.to_rfc3339());
        }
        let timezone = parse_timezone(timezone_hint)?;
        let ndt = NaiveDateTime::parse_from_str(input, &chrono_pattern)
            .map_err(|err| FunctionError::new("DATE_PARSE", err.to_string()))?;
        return timezone
            .from_local_datetime(&ndt)
            .single()
            .map(|dt| dt.to_rfc3339())
            .ok_or_else(|| FunctionError::new("DATE_AMBIGUOUS_LOCAL", "ambiguous local"));
    }

    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(input) {
        return Ok(dt.to_rfc3339());
    }
    let timezone = parse_timezone(timezone_hint)?;
    let ndt = NaiveDateTime::parse_from_str(input, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(input, "%Y-%m-%d %H:%M:%S"))
        .map_err(|err| FunctionError::new("DATE_PARSE", err.to_string()))?;
    timezone
        .from_local_datetime(&ndt)
        .single()
        .map(|dt| dt.to_rfc3339())
        .ok_or_else(|| FunctionError::new("DATE_AMBIGUOUS_LOCAL", "ambiguous"))
}

pub fn format_date_or_datetime(input: &str, pattern: &str) -> Result<String, FunctionError> {
    let chrono_pattern = icuish_to_chrono(pattern);
    if let Ok(date) = NaiveDate::parse_from_str(input, "%Y-%m-%d") {
        return Ok(date.format(&chrono_pattern).to_string());
    }
    let dt = chrono::DateTime::parse_from_rfc3339(input)
        .map_err(|err| FunctionError::new("DATE_PARSE", err.to_string()))?;
    Ok(dt.format(&chrono_pattern).to_string())
}

pub fn today(today_hint: Option<&str>) -> Result<String, FunctionError> {
    today_hint
        .map(ToString::to_string)
        .ok_or_else(|| FunctionError::new("DATE_TODAY_MISSING", "ctx.today not set"))
}

pub fn age_on(birth: &str, reference: &str) -> Result<i64, FunctionError> {
    let birth = parse_iso_date(birth, "DATE_PARSE")?;
    let reference = parse_iso_date(reference, "DATE_PARSE")?;
    let age = reference.year()
        - birth.year()
        - if reference.month() < birth.month()
            || (reference.month() == birth.month() && reference.day() < birth.day())
        {
            1
        } else {
            0
        };
    Ok(age as i64)
}

pub fn years_between(start: &str, end: &str) -> Result<i64, FunctionError> {
    let a = parse_iso_date(start, "DATE_PARSE")?;
    let b = parse_iso_date(end, "DATE_PARSE")?;
    let (start, end) = if a <= b { (a, b) } else { (b, a) };
    let mut years = end.year() - start.year();
    if (end.month(), end.day()) < (start.month(), start.day()) {
        years -= 1;
    }
    Ok(years as i64)
}

pub fn days_between(start: &str, end: &str) -> Result<i64, FunctionError> {
    let a = parse_iso_date(start, "DATE_PARSE")?;
    let b = parse_iso_date(end, "DATE_PARSE")?;
    Ok(b.signed_duration_since(a).num_days())
}

pub fn add_days(input: &str, days: i64) -> Result<String, FunctionError> {
    let date = parse_iso_date(input, "DATE_PARSE")?;
    let out = date
        .checked_add_signed(Duration::days(days))
        .ok_or_else(|| FunctionError::new("DATE_OVERFLOW", "overflow"))?;
    Ok(out.format("%Y-%m-%d").to_string())
}

pub fn add_months(input: &str, months: i64) -> Result<String, FunctionError> {
    let date = parse_iso_date(input, "DATE_PARSE")?;
    let out = add_months_safe(date, months)
        .ok_or_else(|| FunctionError::new("DATE_OVERFLOW", "overflow"))?;
    Ok(out.format("%Y-%m-%d").to_string())
}

pub fn start_of_month(input: &str) -> Result<String, FunctionError> {
    let date = parse_iso_date(input, "DATE_PARSE")?;
    Ok(date
        .with_day(1)
        .ok_or_else(|| FunctionError::new("DATE_OVERFLOW", "overflow"))?
        .format("%Y-%m-%d")
        .to_string())
}

pub fn end_of_month(input: &str) -> Result<String, FunctionError> {
    let date = parse_iso_date(input, "DATE_PARSE")?;
    let (year, month) = if date.month() == 12 {
        (date.year() + 1, 1)
    } else {
        (date.year(), date.month() + 1)
    };
    let first_next = NaiveDate::from_ymd_opt(year, month, 1)
        .ok_or_else(|| FunctionError::new("DATE_OVERFLOW", "overflow"))?;
    Ok(first_next
        .pred_opt()
        .ok_or_else(|| FunctionError::new("DATE_OVERFLOW", "overflow"))?
        .format("%Y-%m-%d")
        .to_string())
}

pub fn min_date(a: &str, b: &str) -> Result<String, FunctionError> {
    let a = parse_iso_date(a, "DATE_PARSE")?;
    let b = parse_iso_date(b, "DATE_PARSE")?;
    Ok(a.min(b).format("%Y-%m-%d").to_string())
}

pub fn max_date(a: &str, b: &str) -> Result<String, FunctionError> {
    let a = parse_iso_date(a, "DATE_PARSE")?;
    let b = parse_iso_date(b, "DATE_PARSE")?;
    Ok(a.max(b).format("%Y-%m-%d").to_string())
}

fn parse_timezone(timezone_hint: Option<&str>) -> Result<Tz, FunctionError> {
    let timezone = timezone_hint.ok_or_else(|| {
        FunctionError::new(
            "DATE_TIMEZONE_REQUIRED",
            "ctx.timezone required for offset-less datetime",
        )
    })?;
    Tz::from_str(timezone)
        .map_err(|_| FunctionError::new("DATE_INVALID_TIMEZONE", "invalid ctx.timezone"))
}

fn parse_iso_date(input: &str, code: &'static str) -> Result<NaiveDate, FunctionError> {
    NaiveDate::parse_from_str(input, "%Y-%m-%d")
        .map_err(|err| FunctionError::new(code, err.to_string()))
}

fn add_months_safe(date: NaiveDate, months: i64) -> Option<NaiveDate> {
    let total = date.month0() as i64 + months;
    let year = date.year() as i64 + total.div_euclid(12);
    let month0 = total.rem_euclid(12) as u32;
    let day = date.day().min(last_day_of_month(year as i32, month0 + 1));
    NaiveDate::from_ymd_opt(year as i32, month0 + 1, day)
}

fn last_day_of_month(year: i32, month: u32) -> u32 {
    (1..=31)
        .rev()
        .find(|day| NaiveDate::from_ymd_opt(year, month, *day).is_some())
        .unwrap_or(28)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datetime_requires_explicit_timezone_for_offsetless_input() {
        let err =
            parse_datetime("2024-01-15 10:30:00", Some("yyyy-MM-dd HH:mm:ss"), None).unwrap_err();
        assert_eq!(err.code, "DATE_TIMEZONE_REQUIRED");
        assert_eq!(
            parse_datetime(
                "2024-01-15 10:30:00",
                Some("yyyy-MM-dd HH:mm:ss"),
                Some("Asia/Bangkok")
            )
            .unwrap(),
            "2024-01-15T10:30:00+07:00"
        );
    }

    #[test]
    fn date_math_matches_current_behavior() {
        assert_eq!(add_months("2024-01-31", 1).unwrap(), "2024-02-29");
        assert_eq!(age_on("2000-05-27", "2026-05-26").unwrap(), 25);
        assert_eq!(years_between("2000-05-27", "2026-05-26").unwrap(), 25);
        assert_eq!(days_between("2024-01-01", "2024-01-03").unwrap(), 2);
        assert_eq!(start_of_month("2024-02-15").unwrap(), "2024-02-01");
        assert_eq!(end_of_month("2024-02-15").unwrap(), "2024-02-29");
    }

    #[test]
    fn end_of_month_extreme_year_returns_err_not_panic() {
        // "262143-12-15" is an extreme 6-digit year; even if parse rejects it, the
        // function must return Err (not panic). Previously the two .unwrap() calls in
        // the body would abort/unwind if NaiveDate construction failed; now they are
        // converted to DATE_OVERFLOW errors via ok_or_else.
        let result = end_of_month("262143-12-15");
        assert!(result.is_err());
    }

    #[test]
    fn start_of_month_normal_date_unchanged() {
        assert_eq!(start_of_month("2024-02-15").unwrap(), "2024-02-01");
    }
}
