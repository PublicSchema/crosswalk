//! Host functions (spec §7) registered under `namespace_function` names (see `expr::rewrite_namespaced_calls`).

use super::helpers::{
    blank_value, coalesce_impl, default_impl, missing_value_bool, null_if_blank_impl, null_if_impl,
    present_value, require_present, value_as_str,
};
use crate::budget;
use crate::eval_ctx::{eval_ctx_get, push_warning};
use crate::missing::{is_missing, missing_value};
use crate::output::{cel_to_json, deep_merge_json, merge_json_objects};
use crate::{FunctionRegistry, FunctionRequestContext, HelperArity, HelperMetadata};
use cel::extractors::Arguments;
use cel::{Context, ExecutionError, Value};
use chrono::{Datelike, NaiveDate};
use regex::Regex;
use serde_json::{Map, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;

fn err_fn(name: &str, m: impl ToString) -> ExecutionError {
    ExecutionError::function_error(name, m)
}

/// Maximum allowed byte length for a user-supplied regex pattern.
/// Patterns longer than this are rejected before compilation to bound
/// worst-case regex-compile time and memory use.
const MAX_REGEX_PATTERN_BYTES: usize = 4096;

/// Compile a regex pattern, returning an [`ExecutionError`] if the pattern
/// exceeds [`MAX_REGEX_PATTERN_BYTES`] or is syntactically invalid.
fn compile_regex(pattern: &str, fn_name: &str) -> Result<Regex, ExecutionError> {
    if pattern.len() > MAX_REGEX_PATTERN_BYTES {
        return Err(err_fn(
            fn_name,
            format!("regex pattern exceeds max {MAX_REGEX_PATTERN_BYTES} bytes"),
        ));
    }
    Regex::new(pattern).map_err(|e| err_fn(fn_name, e))
}

fn arity_error(name: &str, expected: usize, got: usize) -> ExecutionError {
    err_fn(
        name,
        format!(
            "expected {expected} argument{s}, got {got}",
            s = if expected == 1 { "" } else { "s" }
        ),
    )
}

fn str_from(v: &Value) -> Result<String, ExecutionError> {
    value_as_str(v).map_err(|e| err_fn("str", e))
}

pub fn register_crosswalk_functions(
    ctx: &mut Context,
    registry: FunctionRegistry,
    request: FunctionRequestContext,
) {
    crate::eval_ctx::set_eval_ctx(request);
    register_stdlib(ctx, Arc::new(registry));
}

pub fn register_stdlib(ctx: &mut Context, codes: Arc<FunctionRegistry>) {
    // --- 7.1 presence ---
    ctx.add_function(
        "present",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("present", 1, args.len()));
            }
            Ok(present_value(&args[0]).into())
        },
    );
    ctx.add_function(
        "missing",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("missing", 1, args.len()));
            }
            Ok(missing_value_bool(&args[0]).into())
        },
    );
    ctx.add_function(
        "blank",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("blank", 1, args.len()));
            }
            Ok(blank_value(&args[0]).into())
        },
    );
    ctx.add_function(
        "coalesce",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            budget::enforce_max_list_len(args.len())?;
            Ok(coalesce_impl(&args))
        },
    );
    ctx.add_function(
        "default",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("default", 2, args.len()));
            }
            Ok(default_impl(&args[0], &args[1]))
        },
    );
    ctx.add_function(
        "require",
        |v: Value, msg: Value| -> Result<Value, ExecutionError> {
            let m = if matches!(msg, Value::Null) || is_missing(&msg) {
                None
            } else {
                let s = str_from(&msg)?;
                (!s.is_empty()).then_some(s)
            };
            require_present(&v, m).map_err(|e| err_fn("require", e))
        },
    );
    ctx.add_function(
        "null_if",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("null_if", 2, args.len()));
            }
            Ok(null_if_impl(&args[0], &args[1]))
        },
    );
    ctx.add_function(
        "null_if_blank",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("null_if_blank", 1, args.len()));
            }
            Ok(null_if_blank_impl(&args[0]))
        },
    );

    // --- 7.2 type ---
    ctx.add_function(
        "type_string",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("type_string", 1, args.len()));
            }
            Ok(Value::String(Arc::new(str_from(&args[0])?)))
        },
    );
    ctx.add_function(
        "type_int",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("type_int", 1, args.len()));
            }
            let v = args[0].clone();
            if is_missing(&v) || matches!(v, Value::Null) {
                return Err(err_fn("type_int", "cannot parse null/missing as int"));
            }
            match v {
                Value::Int(i) => Ok(Value::Int(i)),
                Value::UInt(u) => i64::try_from(u)
                    .map(Value::Int)
                    .map_err(|_| err_fn("type_int", "integer overflow")),
                Value::Float(f) => {
                    const I64_MAX_PLUS_ONE_AS_F64: f64 = 9_223_372_036_854_775_808.0;
                    if !f.is_finite() {
                        return Err(err_fn("type_int", "non-finite float"));
                    }
                    if f.trunc() != f {
                        return Err(err_fn("type_int", "float must be integral"));
                    }
                    if f < i64::MIN as f64 || f >= I64_MAX_PLUS_ONE_AS_F64 {
                        return Err(err_fn("type_int", "integer overflow"));
                    }
                    Ok(Value::Int(f as i64))
                }
                Value::String(s) => s
                    .trim()
                    .parse::<i64>()
                    .map(Value::Int)
                    .map_err(|e| err_fn("type_int", e)),
                Value::Bool(b) => Ok(Value::Int(if b { 1 } else { 0 })),
                _ => Err(err_fn("type_int", "unsupported type")),
            }
        },
    );
    ctx.add_function(
        "type_float",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("type_float", 1, args.len()));
            }
            let v = args[0].clone();
            if is_missing(&v) || matches!(v, Value::Null) {
                return Err(err_fn("type_float", "cannot parse null/missing"));
            }
            match v {
                Value::Float(f) => Ok(Value::Float(f)),
                Value::Int(i) => Ok(Value::Float(i as f64)),
                Value::UInt(u) => Ok(Value::Float(u as f64)),
                Value::String(s) => s
                    .trim()
                    .parse::<f64>()
                    .map(Value::Float)
                    .map_err(|e| err_fn("type_float", e)),
                _ => Err(err_fn("type_float", "unsupported type")),
            }
        },
    );
    ctx.add_function(
        "type_bool",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("type_bool", 1, args.len()));
            }
            let v = args[0].clone();
            if is_missing(&v) || matches!(v, Value::Null) {
                return Err(err_fn("type_bool", "cannot parse null/missing"));
            }
            match v {
                Value::Bool(b) => Ok(Value::Bool(b)),
                Value::Int(i) => Ok(Value::Bool(i != 0)),
                Value::UInt(u) => Ok(Value::Bool(u != 0)),
                Value::String(s) => {
                    let t = s.trim().to_ascii_lowercase();
                    Ok(Value::Bool(match t.as_str() {
                        "true" | "yes" | "y" | "1" => true,
                        "false" | "no" | "n" | "0" => false,
                        _ => return Err(err_fn("type_bool", "invalid bool string")),
                    }))
                }
                _ => Err(err_fn("type_bool", "unsupported type")),
            }
        },
    );
    ctx.add_function(
        "type_list",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("type_list", 1, args.len()));
            }
            let v = args[0].clone();
            if is_missing(&v) || matches!(v, Value::Null) {
                return Ok(Value::List(Arc::new(vec![])));
            }
            Ok(match v {
                Value::List(l) => Value::List(l.clone()),
                other => Value::List(Arc::new(vec![other.clone()])),
            })
        },
    );
    ctx.add_function(
        "type_map",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("type_map", 1, args.len()));
            }
            match args[0].clone() {
                Value::Map(m) => Ok(Value::Map(m.clone())),
                _ => Err(err_fn("type_map", "not a map")),
            }
        },
    );
    ctx.add_function(
        "type_is_string",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("type_is_string", 1, args.len()));
            }
            Ok(matches!(args[0], Value::String(_)))
        },
    );
    ctx.add_function(
        "type_is_number",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("type_is_number", 1, args.len()));
            }
            Ok(matches!(
                args[0],
                Value::Int(_) | Value::UInt(_) | Value::Float(_)
            ))
        },
    );
    ctx.add_function(
        "type_is_bool",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("type_is_bool", 1, args.len()));
            }
            Ok(matches!(args[0], Value::Bool(_)))
        },
    );
    ctx.add_function(
        "type_is_list",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("type_is_list", 1, args.len()));
            }
            Ok(matches!(args[0], Value::List(_)))
        },
    );
    ctx.add_function(
        "type_is_map",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("type_is_map", 1, args.len()));
            }
            Ok(matches!(args[0], Value::Map(_)))
        },
    );

    // --- 7.3 text ---
    ctx.add_function(
        "text_trim",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("text_trim", 1, args.len()));
            }
            Ok(Value::String(Arc::new(crosswalk_functions::text::trim(
                &str_from(&args[0])?,
            ))))
        },
    );
    ctx.add_function(
        "text_lower",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("text_lower", 1, args.len()));
            }
            Ok(Value::String(Arc::new(
                crosswalk_functions::text::lower_ascii(&str_from(&args[0])?),
            )))
        },
    );
    ctx.add_function(
        "text_upper",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("text_upper", 1, args.len()));
            }
            Ok(Value::String(Arc::new(
                crosswalk_functions::text::upper_ascii(&str_from(&args[0])?),
            )))
        },
    );
    ctx.add_function(
        "text_title",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("text_title", 1, args.len()));
            }
            Ok(Value::String(Arc::new(
                crosswalk_functions::text::title_simple(&str_from(&args[0])?),
            )))
        },
    );
    ctx.add_function(
        "text_normalize_space",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("text_normalize_space", 1, args.len()));
            }
            Ok(Value::String(Arc::new(
                crosswalk_functions::text::normalize_space(&str_from(&args[0])?),
            )))
        },
    );
    ctx.add_function(
        "text_remove_accents",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("text_remove_accents", 1, args.len()));
            }
            Ok(Value::String(Arc::new(
                crosswalk_functions::text::remove_accents(&str_from(&args[0])?),
            )))
        },
    );
    ctx.add_function(
        "text_slug",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("text_slug", 1, args.len()));
            }
            Ok(Value::String(Arc::new(crosswalk_functions::text::slug(
                &str_from(&args[0])?,
            ))))
        },
    );
    ctx.add_function(
        "text_replace",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 3 {
                return Err(arity_error("text_replace", 3, args.len()));
            }
            let s = str_from(&args[0])?;
            let a = str_from(&args[1])?;
            let b = str_from(&args[2])?;
            let out = s.replace(&a, &b);
            budget::enforce_max_string_bytes(out.len())?;
            Ok(Value::String(Arc::new(out)))
        },
    );
    ctx.add_function(
        "text_regex_replace",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 3 {
                return Err(arity_error("text_regex_replace", 3, args.len()));
            }
            let s = str_from(&args[0])?;
            let p = str_from(&args[1])?;
            let r = str_from(&args[2])?;
            let out = crosswalk_functions::text::regex_replace(&s, &p, &r)
                .map_err(|e| err_fn("text_regex_replace", e.message))?;
            budget::enforce_max_string_bytes(out.len())?;
            Ok(Value::String(Arc::new(out)))
        },
    );
    ctx.add_function(
        "text_matches",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("text_matches", 2, args.len()));
            }
            let s = str_from(&args[0])?;
            let p = str_from(&args[1])?;
            let re = compile_regex(&p, "text_matches")?;
            Ok(re.is_match(&s))
        },
    );
    ctx.add_function(
        "text_split",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("text_split", 2, args.len()));
            }
            let s = str_from(&args[0])?;
            let d = str_from(&args[1])?;
            let parts: Vec<Value> = s
                .split(&d)
                .map(|x| Value::String(Arc::new(x.to_string())))
                .collect();
            budget::enforce_max_list_len(parts.len())?;
            Ok(Value::List(Arc::new(parts)))
        },
    );
    ctx.add_function(
        "text_join",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("text_join", 2, args.len()));
            }
            let list = match &args[0] {
                Value::List(l) => l.as_ref().clone(),
                _ => return Err(err_fn("text_join", "expected list")),
            };
            budget::enforce_max_list_len(list.len())?;
            let d = str_from(&args[1])?;
            let mut out = String::new();
            for (i, x) in list.iter().enumerate() {
                if i > 0 {
                    out.push_str(&d);
                }
                out.push_str(&str_from(x)?);
            }
            budget::enforce_max_string_bytes(out.len())?;
            Ok(Value::String(Arc::new(out)))
        },
    );
    ctx.add_function(
        "text_left",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("text_left", 2, args.len()));
            }
            let s = str_from(&args[0])?;
            let n = match &args[1] {
                Value::Int(i) => usize::try_from((*i).max(0)).unwrap_or(0),
                Value::UInt(u) => *u as usize,
                _ => return Err(err_fn("text_left", "second argument must be an integer")),
            };
            Ok(Value::String(Arc::new(s.chars().take(n).collect())))
        },
    );
    ctx.add_function(
        "text_right",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("text_right", 2, args.len()));
            }
            let s = str_from(&args[0])?;
            let n = match &args[1] {
                Value::Int(i) => usize::try_from((*i).max(0)).unwrap_or(0),
                Value::UInt(u) => *u as usize,
                _ => return Err(err_fn("text_right", "second argument must be an integer")),
            };
            let len = s.chars().count();
            let skip = len.saturating_sub(n);
            Ok(Value::String(Arc::new(s.chars().skip(skip).collect())))
        },
    );
    ctx.add_function(
        "text_substr",
        |v: Value, start: i64, len: Value| -> Result<Value, ExecutionError> {
            let s = str_from(&v)?;
            let st = usize::try_from(start.max(0)).unwrap_or(0);
            let chs: Vec<char> = s.chars().collect();
            let slice = if matches!(len, Value::Null) || is_missing(&len) {
                chs.get(st..).unwrap_or(&[])
            } else {
                let l = match len {
                    Value::Int(i) => i,
                    Value::UInt(u) => u as i64,
                    Value::Float(f) => f as i64,
                    _ => str_from(&len)?
                        .parse()
                        .map_err(|e| err_fn("text_substr", e))?,
                };
                let le = usize::try_from(l.max(0)).unwrap_or(0);
                chs.get(st..(st + le).min(chs.len())).unwrap_or(&[])
            };
            Ok(Value::String(Arc::new(slice.iter().collect())))
        },
    );
    ctx.add_function(
        "text_length",
        |Arguments(args): Arguments| -> Result<i64, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("text_length", 1, args.len()));
            }
            Ok(str_from(&args[0])?.chars().count() as i64)
        },
    );
    ctx.add_function(
        "text_contains",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("text_contains", 2, args.len()));
            }
            Ok(str_from(&args[0])?.contains(&str_from(&args[1])?))
        },
    );
    ctx.add_function(
        "text_starts_with",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("text_starts_with", 2, args.len()));
            }
            Ok(str_from(&args[0])?.starts_with(&str_from(&args[1])?))
        },
    );
    ctx.add_function(
        "text_ends_with",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("text_ends_with", 2, args.len()));
            }
            Ok(str_from(&args[0])?.ends_with(&str_from(&args[1])?))
        },
    );
    ctx.add_function(
        "text_regex_extract",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 3 {
                return Err(arity_error("text_regex_extract", 3, args.len()));
            }
            let s = str_from(&args[0])?;
            let p = str_from(&args[1])?;
            let g = match &args[2] {
                Value::Int(i) => usize::try_from((*i).max(0)).unwrap_or(0),
                Value::UInt(u) => *u as usize,
                _ => {
                    return Err(err_fn(
                        "text_regex_extract",
                        "third argument must be an integer",
                    ))
                }
            };
            let extracted = crosswalk_functions::text::regex_extract(&s, &p, g)
                .map_err(|e| err_fn("text_regex_extract", e.message))?
                .unwrap_or_default();
            Ok(Value::String(Arc::new(extracted)))
        },
    );

    // --- 7.4 name ---
    ctx.add_function(
        "name_full",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("name_full", 2, args.len()));
            }
            let g = str_from(&args[0])?.trim().to_string();
            let f = str_from(&args[1])?.trim().to_string();
            let full = format!("{g} {f}").trim().to_string();
            Ok(Value::String(Arc::new(full)))
        },
    );
    ctx.add_function(
        "name_parts",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            use cel::objects::{Key, Map};
            use std::collections::HashMap;
            if args.len() != 1 {
                return Err(arity_error("name_parts", 1, args.len()));
            }
            let s = str_from(&args[0])?;
            let parts: Vec<&str> = s.split_whitespace().collect();
            let mut hm: HashMap<Key, Value> = HashMap::from([
                (Key::String(Arc::new("given".into())), Value::Null),
                (Key::String(Arc::new("middle".into())), Value::Null),
                (Key::String(Arc::new("family".into())), Value::Null),
            ]);
            match parts.len() {
                0 => {}
                1 => {
                    hm.insert(
                        Key::String(Arc::new("given".into())),
                        Value::String(Arc::new(parts[0].to_string())),
                    );
                }
                2 => {
                    hm.insert(
                        Key::String(Arc::new("given".into())),
                        Value::String(Arc::new(parts[0].to_string())),
                    );
                    hm.insert(
                        Key::String(Arc::new("family".into())),
                        Value::String(Arc::new(parts[1].to_string())),
                    );
                }
                _ => {
                    hm.insert(
                        Key::String(Arc::new("given".into())),
                        Value::String(Arc::new(parts[0].to_string())),
                    );
                    hm.insert(
                        Key::String(Arc::new("family".into())),
                        Value::String(Arc::new(parts[parts.len() - 1].to_string())),
                    );
                    let mid = parts[1..parts.len() - 1].join(" ");
                    if !mid.is_empty() {
                        hm.insert(
                            Key::String(Arc::new("middle".into())),
                            Value::String(Arc::new(mid)),
                        );
                    }
                }
            }
            Ok(Value::Map(Map { map: Arc::new(hm) }))
        },
    );
    ctx.add_function(
        "name_initials",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("name_initials", 1, args.len()));
            }
            let s = str_from(&args[0])?;
            let ini: String = s
                .split_whitespace()
                .filter_map(|w| w.chars().next())
                .collect();
            Ok(Value::String(Arc::new(ini)))
        },
    );

    // --- 7.5 date (chrono; ICU subset via pattern translation) ---
    ctx.add_function(
        "date_parse",
        |v: Value, fmt: Value| -> Result<Value, ExecutionError> {
            let s = str_from(&v)?;
            let pat = if matches!(fmt, Value::Null) || is_missing(&fmt) {
                "yyyy-MM-dd".into()
            } else {
                str_from(&fmt)?
            };
            let out = crosswalk_functions::date::parse_date(&s, Some(&pat))
                .map_err(|e| err_fn("date_parse", e.message))?;
            Ok(Value::String(Arc::new(out)))
        },
    );
    ctx.add_function(
        "date_parse_datetime",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            let (v, fmt) = match args.len() {
                1 => (args[0].clone(), Value::Null),
                2 => (args[0].clone(), args[1].clone()),
                n => {
                    return Err(err_fn(
                        "date_parse_datetime",
                        format!("expected 1 or 2 arguments, got {n}"),
                    ))
                }
            };
            let s = str_from(&v)?;
            let pattern = if matches!(fmt, Value::Null) || is_missing(&fmt) {
                None
            } else {
                Some(str_from(&fmt)?)
            };
            let timezone = eval_ctx_get(&["timezone"])
                .and_then(|x| x.as_str().map(|s| s.to_string()))
                .or(None);
            let out = crosswalk_functions::date::parse_datetime(
                &s,
                pattern.as_deref(),
                timezone.as_deref(),
            )
            .map_err(|e| err_fn("date_parse_datetime", e.message))?;
            Ok(Value::String(Arc::new(out)))
        },
    );
    ctx.add_function(
        "date_format",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("date_format", 2, args.len()));
            }
            let s = str_from(&args[0])?;
            let pat = str_from(&args[1])?;
            let out = crosswalk_functions::date::format_date_or_datetime(&s, &pat)
                .map_err(|e| err_fn("date_format", e.message))?;
            Ok(Value::String(Arc::new(out)))
        },
    );
    ctx.add_function(
        "date_is_valid",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("date_is_valid", 1, args.len()));
            }
            Ok(crosswalk_functions::date::parse_date(&str_from(&args[0])?, None).is_ok())
        },
    );
    ctx.add_function(
        "date_today",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if !args.is_empty() {
                return Err(arity_error("date_today", 0, args.len()));
            }
            let t = eval_ctx_get(&["today"]).and_then(|x| x.as_str().map(|s| s.to_string()));
            Ok(Value::String(Arc::new(
                crosswalk_functions::date::today(t.as_deref())
                    .map_err(|e| err_fn("date_today", e.message))?,
            )))
        },
    );
    ctx.add_function(
        "date_age_on",
        |Arguments(args): Arguments| -> Result<i64, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("date_age_on", 2, args.len()));
            }
            crosswalk_functions::date::age_on(&str_from(&args[0])?, &str_from(&args[1])?)
                .map_err(|e| err_fn("date_age_on", e.message))
        },
    );
    ctx.add_function(
        "date_years_between",
        |Arguments(args): Arguments| -> Result<i64, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("date_years_between", 2, args.len()));
            }
            crosswalk_functions::date::years_between(&str_from(&args[0])?, &str_from(&args[1])?)
                .map_err(|e| err_fn("date_years_between", e.message))
        },
    );
    ctx.add_function(
        "date_days_between",
        |Arguments(args): Arguments| -> Result<i64, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("date_days_between", 2, args.len()));
            }
            crosswalk_functions::date::days_between(&str_from(&args[0])?, &str_from(&args[1])?)
                .map_err(|e| err_fn("date_days_between", e.message))
        },
    );
    ctx.add_function(
        "date_add_days",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("date_add_days", 2, args.len()));
            }
            let days = match &args[1] {
                Value::Int(i) => *i,
                Value::UInt(u) => *u as i64,
                _ => {
                    return Err(err_fn(
                        "date_add_days",
                        "second argument must be an integer",
                    ))
                }
            };
            let out = crosswalk_functions::date::add_days(&str_from(&args[0])?, days)
                .map_err(|e| err_fn("date_add_days", e.message))?;
            Ok(Value::String(Arc::new(out)))
        },
    );
    ctx.add_function(
        "date_add_months",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("date_add_months", 2, args.len()));
            }
            let months = match &args[1] {
                Value::Int(i) => *i,
                Value::UInt(u) => *u as i64,
                _ => {
                    return Err(err_fn(
                        "date_add_months",
                        "second argument must be an integer",
                    ))
                }
            };
            let out = crosswalk_functions::date::add_months(&str_from(&args[0])?, months)
                .map_err(|e| err_fn("date_add_months", e.message))?;
            Ok(Value::String(Arc::new(out)))
        },
    );
    ctx.add_function(
        "date_start_of_month",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("date_start_of_month", 1, args.len()));
            }
            let out = crosswalk_functions::date::start_of_month(&str_from(&args[0])?)
                .map_err(|e| err_fn("date_start_of_month", e.message))?;
            Ok(Value::String(Arc::new(out)))
        },
    );
    ctx.add_function(
        "date_end_of_month",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("date_end_of_month", 1, args.len()));
            }
            let out = crosswalk_functions::date::end_of_month(&str_from(&args[0])?)
                .map_err(|e| err_fn("date_end_of_month", e.message))?;
            Ok(Value::String(Arc::new(out)))
        },
    );
    ctx.add_function(
        "date_is_before",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("date_is_before", 2, args.len()));
            }
            let da = NaiveDate::parse_from_str(&str_from(&args[0])?, "%Y-%m-%d")
                .map_err(|e| err_fn("date_is_before", e))?;
            let db = NaiveDate::parse_from_str(&str_from(&args[1])?, "%Y-%m-%d")
                .map_err(|e| err_fn("date_is_before", e))?;
            Ok(da < db)
        },
    );
    ctx.add_function(
        "date_is_after",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("date_is_after", 2, args.len()));
            }
            let da = NaiveDate::parse_from_str(&str_from(&args[0])?, "%Y-%m-%d")
                .map_err(|e| err_fn("date_is_after", e))?;
            let db = NaiveDate::parse_from_str(&str_from(&args[1])?, "%Y-%m-%d")
                .map_err(|e| err_fn("date_is_after", e))?;
            Ok(da > db)
        },
    );
    ctx.add_function(
        "date_min",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("date_min", 2, args.len()));
            }
            let out =
                crosswalk_functions::date::min_date(&str_from(&args[0])?, &str_from(&args[1])?)
                    .map_err(|e| err_fn("date_min", e.message))?;
            Ok(Value::String(Arc::new(out)))
        },
    );
    ctx.add_function(
        "date_max",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("date_max", 2, args.len()));
            }
            let out =
                crosswalk_functions::date::max_date(&str_from(&args[0])?, &str_from(&args[1])?)
                    .map_err(|e| err_fn("date_max", e.message))?;
            Ok(Value::String(Arc::new(out)))
        },
    );

    // --- 7.6 num ---
    ctx.add_function(
        "num_round",
        |v: Value, digits: Value| -> Result<Value, ExecutionError> {
            let x = num_f64(&v)?;
            let d = if matches!(digits, Value::Null) || is_missing(&digits) {
                0i64
            } else {
                match digits {
                    Value::Int(i) => i,
                    Value::UInt(u) => u as i64,
                    Value::Float(f) => f as i64,
                    _ => str_from(&digits)?
                        .parse()
                        .map_err(|e| err_fn("num_round", e))?,
                }
            }
            .clamp(0, 18) as i32;
            let m = 10f64.powi(d);
            Ok(Value::Float((x * m).round() / m))
        },
    );
    ctx.add_function(
        "num_floor",
        |Arguments(args): Arguments| -> Result<i64, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("num_floor", 1, args.len()));
            }
            Ok(num_f64(&args[0])?.floor() as i64)
        },
    );
    ctx.add_function(
        "num_ceil",
        |Arguments(args): Arguments| -> Result<i64, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("num_ceil", 1, args.len()));
            }
            Ok(num_f64(&args[0])?.ceil() as i64)
        },
    );
    ctx.add_function(
        "num_abs",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("num_abs", 1, args.len()));
            }
            Ok(Value::Float(num_f64(&args[0])?.abs()))
        },
    );
    ctx.add_function(
        "num_min",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            budget::enforce_max_list_len(args.len())?;
            let mut m = f64::INFINITY;
            for a in args.iter() {
                m = m.min(num_f64(a)?);
            }
            Ok(Value::Float(m))
        },
    );
    ctx.add_function(
        "num_max",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            budget::enforce_max_list_len(args.len())?;
            let mut m = f64::NEG_INFINITY;
            for a in args.iter() {
                m = m.max(num_f64(a)?);
            }
            Ok(Value::Float(m))
        },
    );
    ctx.add_function(
        "num_clamp",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 3 {
                return Err(arity_error("num_clamp", 3, args.len()));
            }
            let x = num_f64(&args[0])?;
            let a = num_f64(&args[1])?;
            let b = num_f64(&args[2])?;
            Ok(Value::Float(x.clamp(a, b)))
        },
    );
    ctx.add_function(
        "num_is_valid",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("num_is_valid", 1, args.len()));
            }
            Ok(num_f64(&args[0]).is_ok())
        },
    );
    ctx.add_function(
        "num_parse",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("num_parse", 1, args.len()));
            }
            num_f64(&args[0]).map(Value::Float)
        },
    );
    ctx.add_function(
        "num_percent",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("num_percent", 2, args.len()));
            }
            let p = num_f64(&args[0])?;
            let t = num_f64(&args[1])?;
            if t == 0.0 {
                return Err(err_fn("num_percent", "total is zero"));
            }
            Ok(Value::Float(100.0 * p / t))
        },
    );
    ctx.add_function(
        "num_safe_divide",
        |num: Value, den: Value, fb: Value| -> Result<Value, ExecutionError> {
            let n = num_f64(&num).unwrap_or(0.0);
            let d = num_f64(&den).unwrap_or(0.0);
            if d == 0.0 {
                return Ok(if matches!(fb, Value::Null) || is_missing(&fb) {
                    Value::Float(0.0)
                } else {
                    fb
                });
            }
            Ok(Value::Float(n / d))
        },
    );

    // --- 7.7 list ---
    ctx.add_function(
        "list_compact",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("list_compact", 1, args.len()));
            }
            let l = list_ref(&args[0])?;
            budget::enforce_max_list_len(l.len())?;
            let out: Vec<Value> = l.iter().filter(|x| present_value(x)).cloned().collect();
            budget::enforce_max_list_len(out.len())?;
            Ok(Value::List(Arc::new(out)))
        },
    );
    ctx.add_function(
        "list_flatten",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("list_flatten", 1, args.len()));
            }
            let l = list_ref(&args[0])?;
            budget::enforce_max_list_len(l.len())?;
            let mut out = Vec::new();
            flatten_rec(l, &mut out);
            budget::enforce_max_list_len(out.len())?;
            Ok(Value::List(Arc::new(out)))
        },
    );
    ctx.add_function(
        "list_unique",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("list_unique", 1, args.len()));
            }
            let l = list_ref(&args[0])?;
            budget::enforce_max_list_len(l.len())?;
            let mut seen = std::collections::HashSet::new();
            let mut out = Vec::new();
            for x in l.iter().cloned() {
                let key = format!("{:?}", x);
                if seen.insert(key) {
                    out.push(x);
                }
            }
            budget::enforce_max_list_len(out.len())?;
            Ok(Value::List(Arc::new(out)))
        },
    );
    ctx.add_function(
        "list_sort",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("list_sort", 1, args.len()));
            }
            let l = list_ref(&args[0])?;
            budget::enforce_max_list_len(l.len())?;
            let mut l = l.to_vec();
            l.sort_by(|a, b| partial_cmp_vals(a, b).unwrap_or(Ordering::Equal));
            Ok(Value::List(Arc::new(l)))
        },
    );
    ctx.add_function(
        "list_first",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("list_first", 1, args.len()));
            }
            let l = list_ref(&args[0])?;
            Ok(l.first().cloned().unwrap_or(Value::Null))
        },
    );
    ctx.add_function(
        "list_last",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("list_last", 1, args.len()));
            }
            let l = list_ref(&args[0])?;
            Ok(l.last().cloned().unwrap_or(Value::Null))
        },
    );
    ctx.add_function(
        "list_at",
        |v: Value, idx: i64, fb: Value| -> Result<Value, ExecutionError> {
            let l = list_ref(&v)?;
            let i = usize::try_from(idx).ok();
            Ok(i.and_then(|i| l.get(i).cloned()).unwrap_or_else(|| {
                if matches!(fb, Value::Null) || is_missing(&fb) {
                    Value::Null
                } else {
                    fb
                }
            }))
        },
    );
    ctx.add_function(
        "list_length",
        |Arguments(args): Arguments| -> Result<i64, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("list_length", 1, args.len()));
            }
            Ok(list_ref(&args[0])?.len() as i64)
        },
    );
    ctx.add_function(
        "list_contains",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("list_contains", 2, args.len()));
            }
            Ok(list_ref(&args[0])?.contains(&args[1]))
        },
    );
    ctx.add_function(
        "list_join",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("list_join", 2, args.len()));
            }
            let l = list_ref(&args[0])?;
            budget::enforce_max_list_len(l.len())?;
            let d = str_from(&args[1])?;
            let mut out = String::new();
            for (i, x) in l.iter().enumerate() {
                if i > 0 {
                    out.push_str(&d);
                }
                out.push_str(&str_from(x)?);
            }
            budget::enforce_max_string_bytes(out.len())?;
            Ok(Value::String(Arc::new(out)))
        },
    );
    ctx.add_function(
        "list_filter_present",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("list_filter_present", 1, args.len()));
            }
            let l = list_ref(&args[0])?;
            budget::enforce_max_list_len(l.len())?;
            let out: Vec<Value> = l.iter().filter(|x| present_value(x)).cloned().collect();
            budget::enforce_max_list_len(out.len())?;
            Ok(Value::List(Arc::new(out)))
        },
    );
    ctx.add_function(
        "list_of",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            budget::enforce_max_list_len(args.len())?;
            Ok(Value::List(Arc::new(args.to_vec())))
        },
    );
    ctx.add_function(
        "coalesce_list",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            budget::enforce_max_list_len(args.len())?;
            for a in args.iter() {
                if let Value::List(l) = a {
                    if !l.is_empty() {
                        return Ok(a.clone());
                    }
                }
            }
            Ok(Value::List(Arc::new(vec![])))
        },
    );
    ctx.add_function(
        "list_to_map",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("list_to_map", 2, args.len()));
            }
            let l = list_ref(&args[0])?;
            budget::enforce_max_list_len(l.len())?;
            let l = l.to_vec();
            let kf = str_from(&args[1])?;
            let mut hm = std::collections::HashMap::new();
            for item in l {
                let key = map_lookup_value(&item, &kf)
                    .map(|x| str_from(&x))
                    .transpose()?
                    .unwrap_or_default();
                hm.insert(cel::objects::Key::String(Arc::new(key)), item);
            }
            Ok(Value::Map(cel::objects::Map { map: Arc::new(hm) }))
        },
    );

    // --- 7.8 map ---
    ctx.add_function(
        "map_get",
        |obj: Value, path: Value, fb: Value| -> Result<Value, ExecutionError> {
            let p = str_from(&path)?;
            Ok(match map_lookup_value(&obj, &p) {
                Some(v) => v,
                None => {
                    if matches!(fb, Value::Null) || is_missing(&fb) {
                        missing_value()
                    } else {
                        fb
                    }
                }
            })
        },
    );
    ctx.add_function(
        "map_has",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("map_has", 2, args.len()));
            }
            let p = str_from(&args[1])?;
            Ok(map_path_exists(&args[0], &p))
        },
    );
    ctx.add_function(
        "map_pick",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("map_pick", 2, args.len()));
            }
            let m = as_map(&args[0])?;
            let ks = list_ref(&args[1])?;
            budget::enforce_max_list_len(ks.len())?;
            let mut out = std::collections::HashMap::new();
            for k in ks.iter() {
                let key = str_from(k)?;
                if let Some(v) = m.map.get(&cel::objects::Key::String(Arc::new(key.clone()))) {
                    out.insert(cel::objects::Key::String(Arc::new(key)), v.clone());
                }
            }
            Ok(Value::Map(cel::objects::Map { map: Arc::new(out) }))
        },
    );
    ctx.add_function(
        "map_omit",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("map_omit", 2, args.len()));
            }
            let m = as_map(&args[0])?;
            let kref = list_ref(&args[1])?;
            budget::enforce_max_list_len(kref.len())?;
            let ks: std::collections::HashSet<String> =
                kref.iter().map(str_from).collect::<Result<_, _>>()?;
            let mut out = (*m.map).clone();
            out.retain(|k, _| {
                let s = k.to_string();
                !ks.contains(&s)
            });
            Ok(Value::Map(cel::objects::Map { map: Arc::new(out) }))
        },
    );
    ctx.add_function(
        "map_merge",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("map_merge", 2, args.len()));
            }
            let ja = cel_to_json(&args[0]).map_err(|e| err_fn("map_merge", e))?;
            let jb = cel_to_json(&args[1]).map_err(|e| err_fn("map_merge", e))?;
            let merged = merge_json_objects(ja, jb);
            cel::to_value(merged).map_err(|e| err_fn("map_merge", e))
        },
    );
    ctx.add_function(
        "map_deep_merge",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("map_deep_merge", 2, args.len()));
            }
            let ja = cel_to_json(&args[0]).map_err(|e| err_fn("map_deep_merge", e))?;
            let jb = cel_to_json(&args[1]).map_err(|e| err_fn("map_deep_merge", e))?;
            let merged = deep_merge_json(ja, jb);
            cel::to_value(merged).map_err(|e| err_fn("map_deep_merge", e))
        },
    );
    ctx.add_function(
        "map_set",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 3 {
                return Err(arity_error("map_set", 3, args.len()));
            }
            let mut j = cel_to_json(&args[0]).map_err(|e| err_fn("map_set", e))?;
            let p = str_from(&args[1])?;
            let mut vj = cel_to_json(&args[2]).map_err(|e| err_fn("map_set", e))?;
            set_json_path(&mut j, &p, &mut vj)?;
            cel::to_value(j).map_err(|e| err_fn("map_set", e))
        },
    );
    ctx.add_function(
        "map_keys",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("map_keys", 1, args.len()));
            }
            let m = as_map(&args[0])?;
            let keys: Vec<Value> = m
                .map
                .keys()
                .map(|k| Value::String(Arc::new(k.to_string())))
                .collect();
            budget::enforce_max_list_len(keys.len())?;
            Ok(Value::List(Arc::new(keys)))
        },
    );
    ctx.add_function(
        "map_values",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("map_values", 1, args.len()));
            }
            let m = as_map(&args[0])?;
            let vals: Vec<Value> = m.map.values().cloned().collect();
            budget::enforce_max_list_len(vals.len())?;
            Ok(Value::List(Arc::new(vals)))
        },
    );
    ctx.add_function(
        "map_entries",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("map_entries", 1, args.len()));
            }
            let m = as_map(&args[0])?;
            let mut entries = Vec::new();
            for (k, v) in m.map.iter() {
                let mut e = std::collections::HashMap::new();
                e.insert(
                    cel::objects::Key::String(Arc::new("key".into())),
                    Value::String(Arc::new(k.to_string())),
                );
                e.insert(
                    cel::objects::Key::String(Arc::new("value".into())),
                    v.clone(),
                );
                entries.push(Value::Map(cel::objects::Map { map: Arc::new(e) }));
            }
            budget::enforce_max_list_len(entries.len())?;
            Ok(Value::List(Arc::new(entries)))
        },
    );

    ctx.add_function(
        "map_of",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            budget::enforce_max_list_len(args.len())?;
            if args.len() % 2 != 0 {
                return Err(err_fn(
                    "map_of",
                    format!("expected an even number of arguments, got {}", args.len()),
                ));
            }
            let mut out = std::collections::HashMap::new();
            for i in (0..args.len()).step_by(2) {
                let key = match &args[i] {
                    Value::String(s) => s.as_ref().clone(),
                    _ => {
                        return Err(err_fn(
                            "map_of",
                            format!("key at position {i} must be a string"),
                        ))
                    }
                };
                out.insert(
                    cel::objects::Key::String(Arc::new(key)),
                    args[i + 1].clone(),
                );
            }
            Ok(Value::Map(cel::objects::Map { map: Arc::new(out) }))
        },
    );

    // --- 7.9 code ---
    let creg = Arc::clone(&codes);
    ctx.add_function(
        "code_map",
        move |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("code_map", 2, args.len()));
            }
            let s = str_from(&args[0])?;
            let v = str_from(&args[1])?;
            let e = creg
                .map(&s, &v)
                .ok_or_else(|| err_fn("code_map", "unknown code"))?;
            Ok(Value::String(Arc::new(e.id.clone())))
        },
    );
    let creg2 = Arc::clone(&codes);
    ctx.add_function(
        "code_map_or_null",
        move |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("code_map_or_null", 2, args.len()));
            }
            let s = str_from(&args[0])?;
            let v = str_from(&args[1])?;
            Ok(match creg2.map(&s, &v) {
                Some(e) => Value::String(Arc::new(e.id.clone())),
                None => Value::Null,
            })
        },
    );
    let creg3 = Arc::clone(&codes);
    ctx.add_function(
        "code_map_or_default",
        move |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 3 {
                return Err(arity_error("code_map_or_default", 3, args.len()));
            }
            let s = str_from(&args[0])?;
            let v = str_from(&args[1])?;
            Ok(match creg3.map(&s, &v) {
                Some(e) => Value::String(Arc::new(e.id.clone())),
                None => args[2].clone(),
            })
        },
    );
    let creg4 = Arc::clone(&codes);
    ctx.add_function(
        "code_label",
        move |sys: Value, code: Value, loc: Value| -> Result<Value, ExecutionError> {
            let s = str_from(&sys)?;
            let c = str_from(&code)?;
            let locale = if matches!(loc, Value::Null) || is_missing(&loc) {
                "en".to_string()
            } else {
                str_from(&loc)?
            };
            let e = creg4
                .entry_by_canonical(&s, &c)
                .or_else(|| creg4.map(&s, &c))
                .ok_or_else(|| err_fn("code_label", "unknown code"))?;
            let lbl = e
                .label
                .get(&locale)
                .or_else(|| e.label.values().next())
                .cloned()
                .unwrap_or_else(|| e.id.clone());
            Ok(Value::String(Arc::new(lbl)))
        },
    );
    let creg5 = Arc::clone(&codes);
    ctx.add_function(
        "code_exists",
        move |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("code_exists", 2, args.len()));
            }
            let s = str_from(&args[0])?;
            let v = str_from(&args[1])?;
            Ok(creg5.exists(&s, &v))
        },
    );
    let creg6 = Arc::clone(&codes);
    ctx.add_function(
        "code_canonical",
        move |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("code_canonical", 2, args.len()));
            }
            let s = str_from(&args[0])?;
            let v = str_from(&args[1])?;
            let e = creg6
                .map(&s, &v)
                .ok_or_else(|| err_fn("code_canonical", "unknown code"))?;
            let mut m = std::collections::HashMap::new();
            m.insert(
                cel::objects::Key::String(Arc::new("id".into())),
                Value::String(Arc::new(e.id.clone())),
            );
            let lbl = e
                .label
                .get("en")
                .or_else(|| e.label.values().next())
                .cloned()
                .unwrap_or_default();
            m.insert(
                cel::objects::Key::String(Arc::new("label".into())),
                Value::String(Arc::new(lbl)),
            );
            m.insert(
                cel::objects::Key::String(Arc::new("system".into())),
                Value::String(Arc::new(s)),
            );
            for (k, vj) in &e.extra {
                if let Ok(cv) = cel::to_value(vj.clone()) {
                    m.insert(cel::objects::Key::String(Arc::new(k.clone())), cv);
                }
            }
            Ok(Value::Map(cel::objects::Map { map: Arc::new(m) }))
        },
    );
    let creg7 = Arc::clone(&codes);
    ctx.add_function(
        "code_reverse_map",
        move |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("code_reverse_map", 2, args.len()));
            }
            let s = str_from(&args[0])?;
            let c = str_from(&args[1])?;
            Ok(match creg7.reverse_map(&s, &c) {
                Some(x) => Value::String(Arc::new(x)),
                None => Value::Null,
            })
        },
    );
    let creg8 = Arc::clone(&codes);
    ctx.add_function(
        "code_normalize",
        move |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            match args.len() {
                1 => Ok(Value::String(Arc::new(FunctionRegistry::normalize_code(
                    &str_from(&args[0])?,
                )))),
                2 => {
                    let system = str_from(&args[0])?;
                    let value = str_from(&args[1])?;
                    if !creg8.has_system(&system) {
                        return Err(err_fn(
                            "code_normalize",
                            format!("unknown code system: {system}"),
                        ));
                    }
                    let entry = creg8.map(&system, &value).ok_or_else(|| {
                        err_fn("code_normalize", format!("unknown code: {value}"))
                    })?;
                    Ok(Value::String(Arc::new(entry.id.clone())))
                }
                n => Err(err_fn(
                    "code_normalize",
                    format!("expected 1 or 2 arguments, got {n}"),
                )),
            }
        },
    );

    // --- 7.10 id ---
    ctx.add_function(
        "id_make",
        |prefix: Value, Arguments(parts): Arguments| -> Result<Value, ExecutionError> {
            budget::enforce_max_list_len(parts.len().saturating_add(32))?;
            let pfx = str_from(&prefix)?;
            let mut arr = vec![JsonValue::String(pfx.clone())];
            for x in parts.iter() {
                arr.push(cel_to_json(x).map_err(|e| err_fn("id_make", e))?);
            }
            let sorted = sort_json(JsonValue::Array(arr));
            let payload = serde_json::to_string(&sorted).map_err(|e| err_fn("id_make", e))?;
            let mut h = Sha256::new();
            h.update(payload.as_bytes());
            let hex = hex::encode(h.finalize());
            Ok(Value::String(Arc::new(format!("{pfx}_{}", &hex[..32]))))
        },
    );
    ctx.add_function(
        "id_uuid_v5",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("id_uuid_v5", 2, args.len()));
            }
            let n = str_from(&args[0])?;
            let v = str_from(&args[1])?;
            let u = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, format!("{n}:{v}").as_bytes());
            Ok(Value::String(Arc::new(u.to_string())))
        },
    );
    ctx.add_function(
        "id_hash",
        |v: Value, algo: Value| -> Result<Value, ExecutionError> {
            let s = str_from(&v)?;
            let a = if matches!(algo, Value::Null) || is_missing(&algo) {
                "sha256".to_string()
            } else {
                str_from(&algo)?
            };
            if a != "sha256" {
                return Err(err_fn("id_hash", "only sha256 supported"));
            }
            Ok(Value::String(Arc::new(
                crosswalk_functions::ids::stable_hash_sha256(&s, None),
            )))
        },
    );
    ctx.add_function(
        "id_slug",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("id_slug", 2, args.len()));
            }
            let p = str_from(&args[0])?;
            Ok(Value::String(Arc::new(
                crosswalk_functions::ids::prefixed_slug(&p, &str_from(&args[1])?),
            )))
        },
    );
    ctx.add_function(
        "id_clean",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("id_clean", 1, args.len()));
            }
            Ok(Value::String(Arc::new(crosswalk_functions::ids::clean_id(
                &str_from(&args[0])?,
            ))))
        },
    );
    ctx.add_function(
        "id_is_valid",
        |v: Value, pat: Value| -> Result<bool, ExecutionError> {
            let s = str_from(&v)?;
            if !matches!(pat, Value::Null) && !is_missing(&pat) {
                let re = compile_regex(&str_from(&pat)?, "id_is_valid")?;
                return Ok(re.is_match(&s));
            }
            Ok(!s.is_empty())
        },
    );

    // --- 7.11 person ---
    ctx.add_function(
        "person_age",
        |Arguments(args): Arguments| -> Result<i64, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("person_age", 2, args.len()));
            }
            date_age_on_impl(args[0].clone(), args[1].clone())
        },
    );
    ctx.add_function(
        "person_is_minor",
        |bd: Value, rd: Value, th: Value| -> Result<bool, ExecutionError> {
            let age = date_age_on_impl(bd, rd)?;
            let t = if matches!(th, Value::Null) || is_missing(&th) {
                18i64
            } else {
                num_f64(&th)? as i64
            };
            Ok(age < t)
        },
    );
    let creg8 = Arc::clone(&codes);
    ctx.add_function(
        "person_sex_or_gender",
        move |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("person_sex_or_gender", 2, args.len()));
            }
            let s = if matches!(args[1], Value::Null) || is_missing(&args[1]) {
                return Err(err_fn("person_sex_or_gender", "system required"));
            } else {
                str_from(&args[1])?
            };
            let val = str_from(&args[0])?;
            let e = creg8
                .map(&s, &val)
                .ok_or_else(|| err_fn("person_sex_or_gender", "unmapped"))?;
            Ok(Value::String(Arc::new(e.id.clone())))
        },
    );
    ctx.add_function(
        "person_normalize_phone",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("person_normalize_phone", 2, args.len()));
            }
            phone_normalize_impl(args[0].clone(), args[1].clone())
        },
    );

    // --- 7.12 phone ---
    ctx.add_function(
        "phone_normalize",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("phone_normalize", 2, args.len()));
            }
            phone_normalize_impl(args[0].clone(), args[1].clone())
        },
    );
    ctx.add_function(
        "phone_is_valid",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("phone_is_valid", 2, args.len()));
            }
            let Ok(s) = str_from(&args[0]) else {
                return Ok(false);
            };
            Ok(crate::phone::is_valid(&s, &args[1]))
        },
    );
    ctx.add_function(
        "phone_country_code",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("phone_country_code", 2, args.len()));
            }
            let s = str_from(&args[0])?;
            match crate::phone::country_calling_code(&s, &args[1]) {
                Ok(cc) => Ok(Value::String(Arc::new(cc))),
                Err(m) => Err(err_fn("phone_country_code", m)),
            }
        },
    );
    ctx.add_function(
        "phone_mask",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("phone_mask", 1, args.len()));
            }
            let s = str_from(&args[0])?;
            if s.len() <= 4 {
                return Ok(Value::String(Arc::new("*".repeat(s.len()))));
            }
            let vis = 4;
            let masked = "*".repeat(s.len().saturating_sub(vis)) + &s[s.len() - vis..];
            Ok(Value::String(Arc::new(masked)))
        },
    );

    // --- 7.13 email ---
    ctx.add_function(
        "email_normalize",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("email_normalize", 1, args.len()));
            }
            Ok(Value::String(Arc::new(
                crosswalk_functions::email::normalize_email(&str_from(&args[0])?),
            )))
        },
    );
    ctx.add_function(
        "email_is_valid",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("email_is_valid", 1, args.len()));
            }
            let Ok(s) = str_from(&args[0]) else {
                return Ok(false);
            };
            Ok(crosswalk_functions::email::is_valid_email(&s))
        },
    );
    ctx.add_function(
        "email_domain",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("email_domain", 1, args.len()));
            }
            Ok(Value::String(Arc::new(
                crosswalk_functions::email::email_domain(&str_from(&args[0])?).unwrap_or_default(),
            )))
        },
    );

    // --- 7.14 geo ---
    ctx.add_function(
        "geo_point",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("geo_point", 2, args.len()));
            }
            let la = num_f64(&args[0])?;
            let lo = num_f64(&args[1])?;
            let mut m = std::collections::HashMap::new();
            m.insert(
                cel::objects::Key::String(Arc::new("type".into())),
                Value::String(Arc::new("Point".into())),
            );
            m.insert(
                cel::objects::Key::String(Arc::new("coordinates".into())),
                Value::List(Arc::new(vec![Value::Float(lo), Value::Float(la)])),
            );
            Ok(Value::Map(cel::objects::Map { map: Arc::new(m) }))
        },
    );
    ctx.add_function(
        "geo_is_valid_lat",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("geo_is_valid_lat", 1, args.len()));
            }
            Ok(num_f64(&args[0])
                .map(|la| (-90.0..=90.0).contains(&la))
                .unwrap_or(false))
        },
    );
    ctx.add_function(
        "geo_is_valid_lon",
        |Arguments(args): Arguments| -> Result<bool, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("geo_is_valid_lon", 1, args.len()));
            }
            Ok(num_f64(&args[0])
                .map(|lo| (-180.0..=180.0).contains(&lo))
                .unwrap_or(false))
        },
    );
    ctx.add_function(
        "geo_normalize_lat",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("geo_normalize_lat", 1, args.len()));
            }
            num_f64(&args[0]).map(|x| Value::Float(x.clamp(-90.0, 90.0)))
        },
    );
    ctx.add_function(
        "geo_normalize_lon",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("geo_normalize_lon", 1, args.len()));
            }
            num_f64(&args[0]).map(|x| Value::Float(x.clamp(-180.0, 180.0)))
        },
    );
    let creg9 = Arc::clone(&codes);
    ctx.add_function(
        "geo_admin_code",
        move |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("geo_admin_code", 2, args.len()));
            }
            let s = if matches!(args[1], Value::Null) || is_missing(&args[1]) {
                return Err(err_fn("geo_admin_code", "system required"));
            } else {
                str_from(&args[1])?
            };
            let val = str_from(&args[0])?;
            let e = creg9
                .map(&s, &val)
                .ok_or_else(|| err_fn("geo_admin_code", "unmapped"))?;
            Ok(Value::String(Arc::new(e.id.clone())))
        },
    );

    // --- 7.15 address ---
    ctx.add_function(
        "address_line",
        |Arguments(parts): Arguments| -> Result<Value, ExecutionError> {
            budget::enforce_max_list_len(parts.len())?;
            let mut out = Vec::new();
            for p in parts.iter() {
                let s = str_from(p)?.trim().to_string();
                if !s.is_empty() {
                    out.push(s);
                }
            }
            let joined = out.join(", ");
            budget::enforce_max_string_bytes(joined.len())?;
            Ok(Value::String(Arc::new(joined)))
        },
    );
    ctx.add_function(
        "address_normalize_country",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("address_normalize_country", 1, args.len()));
            }
            let s = str_from(&args[0])?.trim().to_ascii_uppercase();
            if s.len() == 2 {
                Ok(Value::String(Arc::new(s)))
            } else {
                Ok(Value::String(Arc::new(FunctionRegistry::normalize_code(
                    &s,
                ))))
            }
        },
    );
    ctx.add_function(
        "address_postal_code",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("address_postal_code", 1, args.len()));
            }
            Ok(Value::String(Arc::new(
                str_from(&args[0])?.trim().to_string(),
            )))
        },
    );

    // --- 7.16 validate ---
    ctx.add_function(
        "validate_required",
        |v: Value, msg: Value| -> Result<Value, ExecutionError> {
            let m = if matches!(msg, Value::Null) || is_missing(&msg) {
                None
            } else {
                let s = str_from(&msg)?;
                (!s.is_empty()).then_some(s)
            };
            require_present(&v, m).map_err(|e| err_fn("validate_required", e))
        },
    );
    ctx.add_function(
        "validate_error",
        |msg: Value, code: Value| -> Result<Value, ExecutionError> {
            let c = if matches!(code, Value::Null) || is_missing(&code) {
                String::new()
            } else {
                str_from(&code)?
            };
            Err(err_fn(
                "validate_error",
                format!("{} [{}]", str_from(&msg)?, c),
            ))
        },
    );
    ctx.add_function(
        "validate_warn",
        |cond: bool, msg: Value, code: Value| -> Result<bool, ExecutionError> {
            if !cond {
                let c = if matches!(code, Value::Null) || is_missing(&code) {
                    String::new()
                } else {
                    str_from(&code)?
                };
                push_warning(format!("{} [{}]", str_from(&msg)?, c));
            }
            Ok(true)
        },
    );
    ctx.add_function(
        "validate_matches",
        |v: Value, pat: Value, msg: Value| -> Result<bool, ExecutionError> {
            let s = str_from(&v)?;
            let re = compile_regex(&str_from(&pat)?, "validate_matches")?;
            if !re.is_match(&s) {
                let m = if matches!(msg, Value::Null) || is_missing(&msg) {
                    "pattern mismatch".into()
                } else {
                    str_from(&msg)?
                };
                return Err(err_fn("validate_matches", m));
            }
            Ok(true)
        },
    );
    ctx.add_function(
        "validate_in",
        |v: Value, allowed: Value, msg: Value| -> Result<bool, ExecutionError> {
            let list = list_ref(&allowed)?;
            budget::enforce_max_list_len(list.len())?;
            if !list.iter().any(|x| x == &v) {
                let m = if matches!(msg, Value::Null) || is_missing(&msg) {
                    "not in allowed set".into()
                } else {
                    str_from(&msg)?
                };
                return Err(err_fn("validate_in", m));
            }
            Ok(true)
        },
    );
    ctx.add_function(
        "validate_range",
        |v: Value, lo: Value, hi: Value, msg: Value| -> Result<bool, ExecutionError> {
            let x = num_f64(&v)?;
            let a = num_f64(&lo)?;
            let b = num_f64(&hi)?;
            if !(x >= a && x <= b) {
                let m = if matches!(msg, Value::Null) || is_missing(&msg) {
                    "out of range".into()
                } else {
                    str_from(&msg)?
                };
                return Err(err_fn("validate_range", m));
            }
            Ok(true)
        },
    );

    // --- 7.17 json ---
    ctx.add_function(
        "json_parse",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("json_parse", 1, args.len()));
            }
            let s = str_from(&args[0])?;
            budget::enforce_max_string_bytes(s.len())?;
            let j: JsonValue = serde_json::from_str(&s).map_err(|e| err_fn("json_parse", e))?;
            cel::to_value(j).map_err(|e| err_fn("json_parse", e))
        },
    );
    ctx.add_function(
        "json_stringify",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("json_stringify", 1, args.len()));
            }
            let j = cel_to_json(&args[0]).map_err(|e| err_fn("json_stringify", e))?;
            let s = serde_json::to_string(&j).map_err(|e| err_fn("json_stringify", e))?;
            budget::enforce_max_string_bytes(s.len())?;
            Ok(Value::String(Arc::new(s)))
        },
    );
    ctx.add_function(
        "json_path",
        |v: Value, path: Value, fb: Value| -> Result<Value, ExecutionError> {
            let p = str_from(&path)?;
            let tail = p.strip_prefix("$.").unwrap_or(&p);
            Ok(map_lookup_value(&v, tail).unwrap_or_else(|| {
                if matches!(fb, Value::Null) || is_missing(&fb) {
                    Value::Null
                } else {
                    fb.clone()
                }
            }))
        },
    );

    // --- 7.18 fhir ---
    ctx.add_function(
        "fhir_reference",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 2 {
                return Err(arity_error("fhir_reference", 2, args.len()));
            }
            let t = str_from(&args[0])?;
            let id = str_from(&args[1])?;
            Ok(Value::String(Arc::new(format!("{t}/{id}"))))
        },
    );

    // --- 7.19 privacy ---
    ctx.add_function(
        "privacy_mask",
        |v: Value, visible_last: Value| -> Result<Value, ExecutionError> {
            let s = str_from(&v)?;
            let n = if matches!(visible_last, Value::Null) || is_missing(&visible_last) {
                4i64
            } else {
                match visible_last {
                    Value::Int(i) => i,
                    Value::UInt(u) => u as i64,
                    Value::Float(f) => f as i64,
                    _ => str_from(&visible_last)?.parse().unwrap_or(4),
                }
            }
            .max(0) as usize;
            Ok(Value::String(Arc::new(
                crosswalk_functions::redaction::mask(&s, n),
            )))
        },
    );
    ctx.add_function(
        "privacy_sha256",
        |v: Value, salt: Value| -> Result<Value, ExecutionError> {
            let salt = if !matches!(salt, Value::Null) && !is_missing(&salt) {
                Some(str_from(&salt)?)
            } else {
                None
            };
            Ok(Value::String(Arc::new(
                crosswalk_functions::ids::stable_hash_sha256(&str_from(&v)?, salt.as_deref()),
            )))
        },
    );
    ctx.add_function(
        "privacy_redact",
        |Arguments(args): Arguments| -> Result<Value, ExecutionError> {
            if args.len() != 1 {
                return Err(arity_error("privacy_redact", 1, args.len()));
            }
            Ok(Value::String(Arc::new(
                crosswalk_functions::redaction::redact(),
            )))
        },
    );
}

fn date_age_on_impl(a: Value, b: Value) -> Result<i64, ExecutionError> {
    let birth = NaiveDate::parse_from_str(&str_from(&a)?, "%Y-%m-%d")
        .map_err(|e| err_fn("date_age_on", e))?;
    let r = NaiveDate::parse_from_str(&str_from(&b)?, "%Y-%m-%d")
        .map_err(|e| err_fn("date_age_on", e))?;
    let age = r.year()
        - birth.year()
        - if r.month() < birth.month() || (r.month() == birth.month() && r.day() < birth.day()) {
            1
        } else {
            0
        };
    Ok(age as i64)
}

fn num_f64(v: &Value) -> Result<f64, ExecutionError> {
    if is_missing(v) || matches!(v, Value::Null) {
        return Err(err_fn("num", "null/missing"));
    }
    match v {
        Value::Float(f) => Ok(*f),
        Value::Int(i) => Ok(*i as f64),
        Value::UInt(u) => Ok(*u as f64),
        Value::String(s) => s.trim().parse().map_err(|e| err_fn("num", e)),
        Value::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
        _ => Err(err_fn("num", "unsupported")),
    }
}

/// Borrow a CEL list slice (no list-length budget; use for read-only access).
fn list_ref(v: &Value) -> Result<&[Value], ExecutionError> {
    match v {
        Value::List(l) => Ok(l.as_ref()),
        _ => Err(err_fn("list", "expected list")),
    }
}

/// Iterative depth-first flatten (left-to-right order).
///
/// Replaces the former recursive implementation to avoid stack overflows on
/// deeply-nested lists.  The output order is identical to what the recursive
/// version produced: items are visited depth-first, left-to-right.
///
/// Implementation: use an explicit work stack of `Value` items, seeded with
/// the input slice in *reverse* order so that `pop()` always yields the next
/// item in the original left-to-right sequence.  When a `List` is popped, its
/// children are pushed in reverse order so they too are processed in order.
fn flatten_rec(items: &[Value], out: &mut Vec<Value>) {
    // Pre-size the stack to the length of the top-level slice.
    let mut stack: Vec<Value> = Vec::with_capacity(items.len());
    // Push in reverse so the first element is at the top of the stack.
    for item in items.iter().rev() {
        stack.push(item.clone());
    }
    while let Some(val) = stack.pop() {
        match val {
            Value::List(inner) => {
                // Push children in reverse so left-to-right order is preserved.
                for item in inner.iter().rev() {
                    stack.push(item.clone());
                }
            }
            other => out.push(other),
        }
    }
}

fn partial_cmp_vals(a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x.partial_cmp(y),
        (Value::Float(x), Value::Float(y)) => x.partial_cmp(y),
        (Value::String(x), Value::String(y)) => x.partial_cmp(y),
        _ => None,
    }
}

fn as_map(v: &Value) -> Result<&cel::objects::Map, ExecutionError> {
    match v {
        Value::Map(m) => Ok(m),
        _ => Err(err_fn("map", "expected map")),
    }
}

fn map_path_exists(obj: &Value, path: &str) -> bool {
    let mut cur = obj;
    for seg in path.split('.') {
        match cur {
            Value::Map(m) => {
                let k = cel::objects::Key::String(Arc::new(seg.to_string()));
                match m.map.get(&k) {
                    Some(next) => cur = next,
                    None => return false,
                }
            }
            _ => return false,
        }
    }
    true
}

fn map_lookup_value(obj: &Value, path: &str) -> Option<Value> {
    let mut cur = obj;
    for seg in path.split('.') {
        match cur {
            Value::Map(m) => {
                let k = cel::objects::Key::String(Arc::new(seg.to_string()));
                match m.map.get(&k) {
                    Some(next) => cur = next,
                    None => return None,
                }
            }
            _ => return None,
        }
    }
    Some(cur.clone())
}

fn set_json_path(
    root: &mut JsonValue,
    path: &str,
    val: &mut JsonValue,
) -> Result<(), ExecutionError> {
    let segs: Vec<&str> = path.split('.').collect();
    if segs.is_empty() {
        return Ok(());
    }
    if !root.is_object() {
        *root = JsonValue::Object(Map::new());
    }
    let last = *segs.last().unwrap();
    let mut cur = root;
    for s in &segs[..segs.len() - 1] {
        if !cur.is_object() {
            *cur = JsonValue::Object(Map::new());
        }
        let o = cur.as_object_mut().unwrap();
        let e = o
            .entry(s.to_string())
            .or_insert_with(|| JsonValue::Object(Map::new()));
        cur = e;
    }
    if let JsonValue::Object(o) = cur {
        o.insert(last.to_string(), val.clone());
    }
    Ok(())
}

fn sort_json(v: JsonValue) -> JsonValue {
    match v {
        JsonValue::Object(m) => {
            let sorted: BTreeMap<_, _> = m.into_iter().map(|(k, v)| (k, sort_json(v))).collect();
            JsonValue::Object(sorted.into_iter().collect())
        }
        JsonValue::Array(a) => JsonValue::Array(a.into_iter().map(sort_json).collect()),
        o => o,
    }
}

fn phone_normalize_impl(v: Value, country: Value) -> Result<Value, ExecutionError> {
    let s = str_from(&v)?;
    match crate::phone::normalize_e164(&s, &country) {
        Ok(out) => Ok(Value::String(Arc::new(out))),
        Err(m) => Err(err_fn("phone_normalize", m)),
    }
}

pub fn helper_metadata() -> Vec<HelperMetadata> {
    [
        // §7.1 presence
        ("present", HelperArity::Exact(1)),
        ("missing", HelperArity::Exact(1)),
        ("blank", HelperArity::Exact(1)),
        ("coalesce", HelperArity::Variadic),
        ("default", HelperArity::Exact(2)),
        ("require", HelperArity::Exact(2)),
        ("null_if", HelperArity::Exact(2)),
        ("null_if_blank", HelperArity::Exact(1)),
        // §7.2 type
        ("type_string", HelperArity::Exact(1)),
        ("type_int", HelperArity::Exact(1)),
        ("type_float", HelperArity::Exact(1)),
        ("type_bool", HelperArity::Exact(1)),
        ("type_list", HelperArity::Exact(1)),
        ("type_map", HelperArity::Exact(1)),
        ("type_is_string", HelperArity::Exact(1)),
        ("type_is_number", HelperArity::Exact(1)),
        ("type_is_bool", HelperArity::Exact(1)),
        ("type_is_list", HelperArity::Exact(1)),
        ("type_is_map", HelperArity::Exact(1)),
        // §7.3 text
        ("text_length", HelperArity::Exact(1)),
        ("text_lower", HelperArity::Exact(1)),
        ("text_upper", HelperArity::Exact(1)),
        ("text_title", HelperArity::Exact(1)),
        ("text_trim", HelperArity::Exact(1)),
        ("text_slug", HelperArity::Exact(1)),
        ("text_left", HelperArity::Exact(2)),
        ("text_right", HelperArity::Exact(2)),
        ("text_substr", HelperArity::Exact(3)),
        ("text_join", HelperArity::Exact(2)),
        ("text_split", HelperArity::Exact(2)),
        ("text_replace", HelperArity::Exact(3)),
        ("text_regex_replace", HelperArity::Exact(3)),
        ("text_remove_accents", HelperArity::Exact(1)),
        ("text_normalize_space", HelperArity::Exact(1)),
        ("text_contains", HelperArity::Exact(2)),
        ("text_starts_with", HelperArity::Exact(2)),
        ("text_ends_with", HelperArity::Exact(2)),
        ("text_matches", HelperArity::Exact(2)),
        ("text_regex_extract", HelperArity::Exact(3)),
        // §7.4 name
        ("name_full", HelperArity::Exact(2)),
        ("name_parts", HelperArity::Exact(1)),
        ("name_initials", HelperArity::Exact(1)),
        // §7.5 date
        ("date_parse", HelperArity::Exact(2)),
        ("date_parse_datetime", HelperArity::OneOrTwo),
        ("date_format", HelperArity::Exact(2)),
        ("date_is_valid", HelperArity::Exact(1)),
        ("date_today", HelperArity::Exact(0)),
        ("date_age_on", HelperArity::Exact(2)),
        ("date_years_between", HelperArity::Exact(2)),
        ("date_days_between", HelperArity::Exact(2)),
        ("date_add_days", HelperArity::Exact(2)),
        ("date_add_months", HelperArity::Exact(2)),
        ("date_start_of_month", HelperArity::Exact(1)),
        ("date_end_of_month", HelperArity::Exact(1)),
        ("date_is_before", HelperArity::Exact(2)),
        ("date_is_after", HelperArity::Exact(2)),
        ("date_min", HelperArity::Exact(2)),
        ("date_max", HelperArity::Exact(2)),
        // §7.6 numeric
        ("num_round", HelperArity::Exact(2)),
        ("num_floor", HelperArity::Exact(1)),
        ("num_ceil", HelperArity::Exact(1)),
        ("num_abs", HelperArity::Exact(1)),
        ("num_min", HelperArity::Variadic),
        ("num_max", HelperArity::Variadic),
        ("num_clamp", HelperArity::Exact(3)),
        ("num_is_valid", HelperArity::Exact(1)),
        ("num_parse", HelperArity::Exact(1)),
        ("num_percent", HelperArity::Exact(2)),
        ("num_safe_divide", HelperArity::Exact(3)),
        // §7.7 list
        ("list_compact", HelperArity::Exact(1)),
        ("list_flatten", HelperArity::Exact(1)),
        ("list_unique", HelperArity::Exact(1)),
        ("list_sort", HelperArity::Exact(1)),
        ("list_first", HelperArity::Exact(1)),
        ("list_last", HelperArity::Exact(1)),
        ("list_at", HelperArity::Exact(3)),
        ("list_length", HelperArity::Exact(1)),
        ("list_contains", HelperArity::Exact(2)),
        ("list_join", HelperArity::Exact(2)),
        ("list_filter_present", HelperArity::Exact(1)),
        ("list_of", HelperArity::Variadic),
        ("coalesce_list", HelperArity::Variadic),
        ("list_to_map", HelperArity::Exact(2)),
        // §7.8 map
        ("map_get", HelperArity::Exact(3)),
        ("map_has", HelperArity::Exact(2)),
        ("map_pick", HelperArity::Exact(2)),
        ("map_omit", HelperArity::Exact(2)),
        ("map_merge", HelperArity::Exact(2)),
        ("map_deep_merge", HelperArity::Exact(2)),
        ("map_set", HelperArity::Exact(3)),
        ("map_keys", HelperArity::Exact(1)),
        ("map_values", HelperArity::Exact(1)),
        ("map_entries", HelperArity::Exact(1)),
        ("map_of", HelperArity::Variadic),
        // §7.9 code system
        ("code_map", HelperArity::Exact(2)),
        ("code_map_or_null", HelperArity::Exact(2)),
        ("code_map_or_default", HelperArity::Exact(3)),
        ("code_label", HelperArity::Exact(3)),
        ("code_exists", HelperArity::Exact(2)),
        ("code_canonical", HelperArity::Exact(2)),
        ("code_reverse_map", HelperArity::Exact(2)),
        ("code_normalize", HelperArity::OneOrTwo),
        // §7.10 id
        ("id_make", HelperArity::Variadic),
        ("id_uuid_v5", HelperArity::Exact(2)),
        ("email_normalize", HelperArity::Exact(1)),
        ("id_hash", HelperArity::Exact(2)),
        ("id_slug", HelperArity::Exact(2)),
        ("id_clean", HelperArity::Exact(1)),
        ("id_is_valid", HelperArity::Exact(2)),
        // §7.11 person
        ("person_age", HelperArity::Exact(2)),
        ("person_is_minor", HelperArity::Exact(3)),
        ("person_sex_or_gender", HelperArity::Exact(2)),
        ("person_normalize_phone", HelperArity::Exact(2)),
        // §7.12 phone
        ("phone_normalize", HelperArity::Exact(2)),
        ("phone_is_valid", HelperArity::Exact(2)),
        ("phone_country_code", HelperArity::Exact(2)),
        ("phone_mask", HelperArity::Exact(1)),
        // §7.13 email
        ("email_is_valid", HelperArity::Exact(1)),
        ("email_domain", HelperArity::Exact(1)),
        // §7.14 geo
        ("geo_point", HelperArity::Exact(2)),
        ("geo_is_valid_lat", HelperArity::Exact(1)),
        ("geo_is_valid_lon", HelperArity::Exact(1)),
        ("geo_normalize_lat", HelperArity::Exact(1)),
        ("geo_normalize_lon", HelperArity::Exact(1)),
        ("geo_admin_code", HelperArity::Exact(2)),
        // §7.15 address
        ("address_line", HelperArity::Variadic),
        ("address_normalize_country", HelperArity::Exact(1)),
        ("address_postal_code", HelperArity::Exact(1)),
        // §7.16 validation
        ("validate_required", HelperArity::Exact(2)),
        ("validate_error", HelperArity::Exact(2)),
        ("validate_warn", HelperArity::Exact(3)),
        ("validate_matches", HelperArity::Exact(3)),
        ("validate_in", HelperArity::Exact(3)),
        ("validate_range", HelperArity::Exact(4)),
        // §7.17 json
        ("json_parse", HelperArity::Exact(1)),
        ("json_stringify", HelperArity::Exact(1)),
        ("json_path", HelperArity::Exact(3)),
        // §7.18 fhir
        ("fhir_reference", HelperArity::Exact(2)),
        // §7.19 privacy
        ("privacy_mask", HelperArity::Exact(2)),
        ("privacy_sha256", HelperArity::Exact(2)),
        ("privacy_redact", HelperArity::Exact(1)),
    ]
    .into_iter()
    .map(|(name, arity)| HelperMetadata { name, arity })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Helper: build a Value::List from a Vec<Value>.
    fn list(items: Vec<Value>) -> Value {
        Value::List(Arc::new(items))
    }

    fn int(n: i64) -> Value {
        Value::Int(n)
    }

    // --- F5: flatten_rec tests ---

    /// Verify that the iterative flatten produces the same depth-first
    /// left-to-right order as the original recursive version.
    #[test]
    fn test_flatten_rec_order_preservation() {
        // Input: [1, [2, [3, 4], 5], 6]
        // Expected output: [1, 2, 3, 4, 5, 6]
        let input = vec![
            int(1),
            list(vec![int(2), list(vec![int(3), int(4)]), int(5)]),
            int(6),
        ];
        let mut out = Vec::new();
        flatten_rec(&input, &mut out);
        let expected: Vec<Value> = (1..=6).map(int).collect();
        assert_eq!(
            out, expected,
            "flatten_rec should produce depth-first left-to-right order"
        );
    }

    /// Verify that a deeply-nested list (~5000 levels) does NOT overflow the
    /// stack.  This would have caused a stack overflow with the old recursive
    /// implementation.
    #[test]
    fn test_flatten_rec_deep_no_stack_overflow() {
        // Build a left-nested list 5000 levels deep.
        // The deepest value is 1, and each nesting wraps it: [[[[...1...]]]]
        // Flat output should be [1].
        const DEPTH: usize = 5_000;
        let mut v: Value = int(42);
        for _ in 0..DEPTH {
            v = list(vec![v]);
        }
        let mut out = Vec::new();
        flatten_rec(&[v], &mut out);
        assert_eq!(out, vec![int(42)], "deep flatten should yield [42]");
    }

    // --- F6: compile_regex tests ---

    #[test]
    fn test_compile_regex_valid_pattern_succeeds() {
        let re = compile_regex(r"^\d{4}-\d{2}-\d{2}$", "test_fn");
        assert!(
            re.is_ok(),
            "a valid short pattern should compile successfully"
        );
        let re = re.unwrap();
        assert!(re.is_match("2024-01-15"));
        assert!(!re.is_match("not-a-date"));
    }

    #[test]
    fn test_compile_regex_pattern_too_long_returns_error() {
        // Build a pattern that exceeds MAX_REGEX_PATTERN_BYTES.
        let long_pattern = "a".repeat(MAX_REGEX_PATTERN_BYTES + 1);
        let result = compile_regex(&long_pattern, "test_fn");
        assert!(
            result.is_err(),
            "a pattern exceeding the byte limit should return an error"
        );
        // Verify the error message mentions the limit.
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains(&MAX_REGEX_PATTERN_BYTES.to_string()),
            "error message should mention the byte limit, got: {msg}"
        );
    }

    #[test]
    fn test_compile_regex_exactly_at_limit_succeeds() {
        // A pattern of exactly MAX_REGEX_PATTERN_BYTES bytes should be accepted.
        let pattern = "a".repeat(MAX_REGEX_PATTERN_BYTES);
        let result = compile_regex(&pattern, "test_fn");
        assert!(
            result.is_ok(),
            "a pattern of exactly MAX_REGEX_PATTERN_BYTES should be accepted"
        );
    }

    #[test]
    fn test_compile_regex_invalid_pattern_returns_error() {
        // An invalid regex should produce an error.
        let result = compile_regex("[unclosed", "test_fn");
        assert!(
            result.is_err(),
            "an invalid regex pattern should return an error"
        );
    }
}
