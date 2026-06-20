use crate::FunctionError;
use unicode_normalization::UnicodeNormalization;

const MAX_REGEX_PATTERN_BYTES: usize = 4096;

pub fn trim(input: &str) -> String {
    input.trim().to_string()
}

pub fn lower_ascii(input: &str) -> String {
    input.to_ascii_lowercase()
}

pub fn upper_ascii(input: &str) -> String {
    input.to_ascii_uppercase()
}

pub fn title_simple(input: &str) -> String {
    input
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn normalize_space(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn remove_accents(input: &str) -> String {
    input
        .nfd()
        .filter(|ch| !unicode_normalization::char::is_combining_mark(*ch))
        .collect()
}

pub fn slug(input: &str) -> String {
    input
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn regex_replace(
    input: &str,
    pattern: &str,
    replacement: &str,
) -> Result<String, FunctionError> {
    if pattern.len() > MAX_REGEX_PATTERN_BYTES {
        return Err(FunctionError::new(
            "REGEX_PATTERN_TOO_LONG",
            format!("regex pattern exceeds max {MAX_REGEX_PATTERN_BYTES} bytes"),
        ));
    }
    let re = regex::Regex::new(pattern)
        .map_err(|err| FunctionError::new("REGEX_INVALID_PATTERN", err.to_string()))?;
    Ok(re.replace_all(input, replacement).to_string())
}

pub fn regex_extract(
    input: &str,
    pattern: &str,
    group: usize,
) -> Result<Option<String>, FunctionError> {
    if pattern.len() > MAX_REGEX_PATTERN_BYTES {
        return Err(FunctionError::new(
            "REGEX_PATTERN_TOO_LONG",
            format!("regex pattern exceeds max {MAX_REGEX_PATTERN_BYTES} bytes"),
        ));
    }
    let re = regex::Regex::new(pattern)
        .map_err(|err| FunctionError::new("REGEX_INVALID_PATTERN", err.to_string()))?;
    Ok(re.captures(input).and_then(|captures| {
        captures
            .get(group)
            .map(|matched| matched.as_str().to_string())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_helpers_preserve_current_semantics() {
        assert_eq!(trim("  a  "), "a");
        assert_eq!(lower_ascii("ÄBC"), "Äbc");
        assert_eq!(upper_ascii("äbc"), "äBC");
        assert_eq!(title_simple("ada  lovelace"), "Ada Lovelace");
        assert_eq!(normalize_space(" a\tb\n c "), "a b c");
        assert_eq!(remove_accents("Crème Brûlée"), "Creme Brulee");
        assert_eq!(slug("Hello, WORLD!"), "hello-world");
    }

    #[test]
    fn regex_extract_no_match_is_none() {
        assert_eq!(regex_extract("hello", r"\d+", 0).unwrap(), None);
    }

    #[test]
    fn regex_errors_have_stable_codes() {
        let err = regex_replace("x", "[", "").unwrap_err();
        assert_eq!(err.code, "REGEX_INVALID_PATTERN");
    }

    #[test]
    fn regex_replace_pattern_too_long_returns_err() {
        let long_pattern = "a".repeat(MAX_REGEX_PATTERN_BYTES + 1);
        let err = regex_replace("hello", &long_pattern, "").unwrap_err();
        assert_eq!(err.code, "REGEX_PATTERN_TOO_LONG");
    }

    #[test]
    fn regex_replace_short_pattern_still_works() {
        assert_eq!(
            regex_replace("hello world", r"\s+", "-").unwrap(),
            "hello-world"
        );
    }

    #[test]
    fn regex_extract_pattern_too_long_returns_err() {
        let long_pattern = "b".repeat(MAX_REGEX_PATTERN_BYTES + 1);
        let err = regex_extract("hello", &long_pattern, 0).unwrap_err();
        assert_eq!(err.code, "REGEX_PATTERN_TOO_LONG");
    }

    #[test]
    fn regex_extract_short_pattern_still_works() {
        assert_eq!(
            regex_extract("hello 42 world", r"\d+", 0).unwrap(),
            Some("42".to_string())
        );
    }
}
