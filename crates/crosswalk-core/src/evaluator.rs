//! Mapping evaluation (CEL programs, record/field loop).
#![allow(clippy::result_large_err, clippy::too_many_arguments)]

use crate::compiled::CompiledCel;
use crate::compiled::{CompiledMapping, CompiledRecord, ErrorMode};
use crate::errors::{ErrorCode, ExpressionPreviewResult, MappingError, StandaloneEvalError};
use crate::mapping::FieldYaml;
use crate::missing::MISSING_STR;
use crate::output::omit_null_keys;
use crate::paths::{
    augment_json_with_paths, augment_loop_element, build_binding_envelope,
    collect_dotted_paths_with_roots, collect_missing_aware_injection_paths_from_compiled,
    filter_paths_by_roots,
};
use crate::security::SecurityLimits;
use serde_json::{Map, Value as JsonValue};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::sync::Arc;

pub use crosswalk_cel::StandaloneExpressionInput;

pub fn evaluate_mapping(
    mapping: &CompiledMapping,
    source: JsonValue,
    ctx: JsonValue,
) -> crate::runtime::MappingOutput {
    evaluate_mapping_with_limits(mapping, source, ctx, &SecurityLimits::default())
}

pub fn evaluate_mapping_with_limits(
    mapping: &CompiledMapping,
    source: JsonValue,
    ctx: JsonValue,
    limits: &SecurityLimits,
) -> crate::runtime::MappingOutput {
    let mut records: BTreeMap<String, Vec<JsonValue>> = BTreeMap::new();
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mode = mapping.error_mode;
    let codes = Arc::clone(&mapping.code_systems);

    let paths = collect_mapping_paths(mapping);
    let (src_json, root_json, ctx_json) = build_binding_envelope(source, ctx, &paths, MISSING_STR);

    for v in &mapping.validations {
        match eval_compiled_json(
            &v.cel,
            &src_json,
            &root_json,
            &ctx_json,
            JsonValue::Object(Map::new()),
            None,
            None,
            None,
            limits,
            &codes,
        ) {
            Ok(val) if truthy_json(&val) => {}
            Ok(_) => {
                let err = MappingError::error(
                    ErrorCode::ValidationError,
                    v.message.clone(),
                    Some(v.path.clone()),
                    Some(v.cel.source.clone()),
                );
                let mut err = err;
                err.source_path = crate::paths::primary_binding_hint(&v.cel.source);
                if matches!(mode, ErrorMode::Lenient) {
                    warnings.push(err.warning());
                } else {
                    errors.push(err);
                }
            }
            Err(e) => {
                let err = exec_validation_err(&v.path, &v.cel.source, &v.message, e);
                if matches!(mode, ErrorMode::Lenient) {
                    warnings.push(err.warning());
                } else {
                    errors.push(err);
                }
            }
        }
    }

    if matches!(mode, ErrorMode::Strict) && !errors.is_empty() {
        return crate::runtime::MappingOutput {
            records,
            warnings,
            errors,
        };
    }

    for rec in &mapping.records {
        match eval_record(
            rec,
            &src_json,
            &root_json,
            &ctx_json,
            &codes,
            mode,
            &mut errors,
            &mut warnings,
            &paths,
            limits,
        ) {
            Ok(rows) => {
                records.insert(rec.name.clone(), rows);
            }
            Err(e) => {
                errors.push(e);
                if matches!(mode, ErrorMode::Strict) {
                    break;
                }
            }
        }
    }

    crate::runtime::MappingOutput {
        records,
        warnings,
        errors,
    }
}

fn collect_mapping_paths(mapping: &CompiledMapping) -> Vec<(String, Vec<String>)> {
    // Build a flat list of all compiled programs in this mapping so we can
    // perform AST-based classification (missing-aware vs strict context).
    let mut programs: Vec<&CompiledCel> = Vec::new();
    for v in &mapping.validations {
        programs.push(&v.cel);
    }
    for rec in &mapping.records {
        if let Some(em) = &rec.emit {
            programs.push(em);
        }
        if let Some(fx) = &rec.foreach {
            programs.push(fx);
        }
        if let Some(w) = &rec.when {
            programs.push(w);
        }
        for (_, cel) in &rec.vars {
            programs.push(cel);
        }
        for field in &rec.fields {
            programs.push(&field.cel);
        }
    }
    let mut paths = collect_missing_aware_injection_paths_from_compiled(&programs);

    // For custom `foreach.as` bindings (non-standard root names like a user-defined
    // alias), AST classification cannot infer the root from the standard set.
    // Fall back to regex-based collection for those extra roots only.
    for rec in &mapping.records {
        let Some(as_name) = rec.r#as.as_deref() else {
            continue;
        };
        if matches!(as_name, "item" | "member") {
            continue;
        }
        let mut row_exprs = Vec::new();
        if let Some(when) = &rec.when {
            row_exprs.push(when.source.clone());
        }
        for (_, cel) in &rec.vars {
            row_exprs.push(cel.source.clone());
        }
        for field in &rec.fields {
            row_exprs.push(field.cel.source.clone());
        }
        paths.extend(collect_dotted_paths_with_roots(&row_exprs, &[as_name]));
    }
    paths.sort();
    paths.dedup();
    paths
}

/// `on_error` when an expression fails (spec §5.4): required is always `fail`; optional defaults
/// to `fail` in strict/collect and `null` in lenient.
fn field_error_policy(mode: ErrorMode, required: bool, explicit: Option<&str>) -> String {
    if required {
        return "fail".into();
    }
    let d = match mode {
        ErrorMode::Lenient => "null",
        ErrorMode::Strict | ErrorMode::Collect => "fail",
    };
    match explicit {
        None => d.into(),
        Some(s @ ("fail" | "null" | "omit" | "default")) => s.into(),
        Some(_) => d.into(),
    }
}

fn eval_record(
    rec: &CompiledRecord,
    source: &JsonValue,
    root: &JsonValue,
    ctx: &JsonValue,
    codes: &Arc<crate::code_system::CodeSystemRegistry>,
    mode: ErrorMode,
    collected: &mut Vec<MappingError>,
    warnings: &mut Vec<MappingError>,
    all_paths: &[(String, Vec<String>)],
    limits: &SecurityLimits,
) -> Result<Vec<JsonValue>, MappingError> {
    let mut out = Vec::new();

    if let Some(fx) = &rec.foreach {
        let list_v = match eval_compiled_json(
            fx,
            source,
            root,
            ctx,
            JsonValue::Object(Map::new()),
            None,
            None,
            None,
            limits,
            codes,
        ) {
            Ok(v) => v,
            Err(e) => {
                let err = exec_mapping_err_path(&rec.name, "foreach", e, "foreach", &fx.source);
                return match mode {
                    ErrorMode::Strict => Err(err),
                    ErrorMode::Lenient => {
                        warnings.push(err.warning());
                        Ok(vec![])
                    }
                    ErrorMode::Collect => {
                        collected.push(err);
                        Ok(vec![])
                    }
                };
            }
        };
        let items = match list_v {
            JsonValue::Array(items) => items,
            _ => {
                return Err(MappingError::error(
                    ErrorCode::TypeError,
                    "foreach must evaluate to a list",
                    Some(format!("records.{}", rec.name)),
                    None,
                ));
            }
        };
        let as_name = rec.r#as.clone().unwrap_or_else(|| "item".into());
        let mut row_roots = vec!["item", "member"];
        if as_name != "item" && as_name != "member" {
            row_roots.push(as_name.as_str());
        }
        let row_paths = filter_paths_by_roots(all_paths, &row_roots);
        for (index, item_json) in items.into_iter().enumerate() {
            let aug_json =
                augment_loop_element(&item_json, &row_paths, as_name.as_str(), MISSING_STR);
            if let Some(w) = &rec.when {
                let wv = match eval_compiled_json(
                    w,
                    source,
                    root,
                    ctx,
                    JsonValue::Object(Map::new()),
                    Some(&aug_json),
                    Some(index as i64),
                    Some(as_name.as_str()),
                    limits,
                    codes,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        let err = exec_mapping_err_path(&rec.name, "when", e, "when", &w.source)
                            .with_record(rec.name.clone(), Some(index));
                        match mode {
                            ErrorMode::Strict => return Err(err),
                            ErrorMode::Lenient => {
                                warnings.push(err.warning());
                                continue;
                            }
                            ErrorMode::Collect => {
                                collected.push(err);
                                continue;
                            }
                        }
                    }
                };
                if !truthy_json(&wv) {
                    continue;
                }
            }
            if let Some(row) = eval_record_row(
                rec,
                source,
                root,
                ctx,
                &aug_json,
                index as i64,
                as_name.as_str(),
                codes,
                mode,
                collected,
                warnings,
                Some(index),
                all_paths,
                limits,
            )? {
                out.push(row);
            }
        }
        return Ok(out);
    }

    if let Some(em) = &rec.emit {
        let ev = match eval_compiled_json(
            em,
            source,
            root,
            ctx,
            JsonValue::Object(Map::new()),
            None,
            None,
            None,
            limits,
            codes,
        ) {
            Ok(v) => v,
            Err(e) => {
                let err = exec_mapping_err_path(&rec.name, "emit", e, "emit", &em.source);
                return match mode {
                    ErrorMode::Strict => Err(err),
                    ErrorMode::Lenient => {
                        warnings.push(err.warning());
                        Ok(vec![])
                    }
                    ErrorMode::Collect => {
                        collected.push(err);
                        Ok(vec![])
                    }
                };
            }
        };
        if !truthy_json(&ev) {
            return Ok(vec![]);
        }
    }

    let row_paths = filter_paths_by_roots(all_paths, &["item", "member"]);
    let aug_json = augment_loop_element(&JsonValue::Null, &row_paths, "item", MISSING_STR);
    if let Some(row) = eval_record_row(
        rec, source, root, ctx, &aug_json, -1, "item", codes, mode, collected, warnings, None,
        all_paths, limits,
    )? {
        out.push(row);
    }
    Ok(out)
}

fn eval_record_row(
    rec: &CompiledRecord,
    source: &JsonValue,
    root: &JsonValue,
    ctx: &JsonValue,
    item: &JsonValue,
    index: i64,
    as_name: &str,
    codes: &Arc<crate::code_system::CodeSystemRegistry>,
    mode: ErrorMode,
    collected: &mut Vec<MappingError>,
    warnings: &mut Vec<MappingError>,
    row_index: Option<usize>,
    all_paths: &[(String, Vec<String>)],
    limits: &SecurityLimits,
) -> Result<Option<JsonValue>, MappingError> {
    let vars_paths = filter_paths_by_roots(all_paths, &["vars"]);
    let mut vars_json = if vars_paths.is_empty() {
        Map::new()
    } else {
        let mut wrap = Map::new();
        wrap.insert("vars".into(), JsonValue::Object(Map::new()));
        let mut env = JsonValue::Object(wrap);
        augment_json_with_paths(&mut env, &vars_paths, MISSING_STR);
        env.get("vars")
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default()
    };

    for (vn, prog) in &rec.vars {
        let v = match eval_compiled_json(
            prog,
            source,
            root,
            ctx,
            JsonValue::Object(vars_json.clone()),
            Some(item),
            Some(index),
            Some(as_name),
            limits,
            codes,
        ) {
            Ok(v) => v,
            Err(e) => {
                let err =
                    exec_mapping_err_path(&rec.name, vn, e, &format!("vars.{vn}"), &prog.source)
                        .with_record(rec.name.clone(), row_index);
                match mode {
                    ErrorMode::Strict => return Err(err),
                    ErrorMode::Lenient => {
                        warnings.push(err.warning());
                    }
                    ErrorMode::Collect => {
                        collected.push(err);
                    }
                }
                JsonValue::Null
            }
        };
        vars_json.insert(vn.clone(), v.clone());
    }

    let mut obj = Map::new();
    for cf in &rec.fields {
        let path = format!("records.{}.fields.{}", rec.name, cf.name);
        let res = eval_compiled_json(
            &cf.cel,
            source,
            root,
            ctx,
            JsonValue::Object(vars_json.clone()),
            Some(item),
            Some(index),
            Some(as_name),
            limits,
            codes,
        );
        let (required, on_err, defv) = match &cf.yaml {
            FieldYaml::Short(_) => (false, None, None),
            FieldYaml::Long {
                required,
                on_error,
                default,
                ..
            } => (*required, on_error.clone(), default.clone()),
        };
        let output_on_err: Option<&str> = match (&cf.yaml, required, mode) {
            (FieldYaml::Short(_), false, ErrorMode::Lenient) => Some("null"),
            _ => on_err.as_deref(),
        };

        match res {
            Ok(j) => {
                if j.is_null() && required {
                    if matches!(mode, ErrorMode::Strict) {
                        return Err(mapping_err_with_expr(
                            ErrorCode::MissingRequiredValue,
                            format!("required field {}", cf.name),
                            Some(path),
                            &cf.cel.source,
                        ));
                    }
                    collected.push(
                        mapping_err_with_expr(
                            ErrorCode::MissingRequiredValue,
                            format!("required field {}", cf.name),
                            Some(path),
                            &cf.cel.source,
                        )
                        .with_record(rec.name.clone(), row_index),
                    );
                    return Ok(None);
                }
                apply_field_output(&mut obj, &cf.name, j, output_on_err, defv)?;
            }
            Err(e) => {
                if required {
                    if matches!(mode, ErrorMode::Strict) {
                        return Err(exec_mapping_err_path(
                            &rec.name,
                            &cf.name,
                            e,
                            &cf.name,
                            &cf.cel.source,
                        ));
                    }
                    collected.push(
                        exec_mapping_err_path(
                            &rec.name,
                            &cf.name,
                            e.clone(),
                            &cf.name,
                            &cf.cel.source,
                        )
                        .with_record(rec.name.clone(), row_index),
                    );
                    return Ok(None);
                }
                let policy = field_error_policy(mode, required, on_err.as_deref());
                if matches!(mode, ErrorMode::Strict) && policy.as_str() == "fail" {
                    return Err(exec_mapping_err_path(
                        &rec.name,
                        &cf.name,
                        e,
                        &cf.name,
                        &cf.cel.source,
                    ));
                }
                if matches!(mode, ErrorMode::Collect) && policy.as_str() == "fail" {
                    collected.push(
                        exec_mapping_err_path(
                            &rec.name,
                            &cf.name,
                            e.clone(),
                            &cf.name,
                            &cf.cel.source,
                        )
                        .with_record(rec.name.clone(), row_index),
                    );
                }
                if matches!(mode, ErrorMode::Lenient) {
                    warnings.push(
                        exec_mapping_err_path(
                            &rec.name,
                            &cf.name,
                            e.clone(),
                            &cf.name,
                            &cf.cel.source,
                        )
                        .with_record(rec.name.clone(), row_index)
                        .warning(),
                    );
                }
                // Collect + default `fail`, and lenient + explicit `fail` on optional fields: still emit
                // a partial row (null field) instead of aborting the row via `apply_field_error_output("fail", ...)`.
                let apply_policy = if (matches!(mode, ErrorMode::Collect)
                    || matches!(mode, ErrorMode::Lenient))
                    && policy.as_str() == "fail"
                {
                    "null"
                } else {
                    policy.as_str()
                };
                apply_field_error_output(
                    &mut obj,
                    &cf.name,
                    &path,
                    apply_policy,
                    defv,
                    e,
                    &cf.cel.source,
                )?;
            }
        }
    }

    Ok(Some(JsonValue::Object(obj)))
}

fn apply_field_output(
    obj: &mut Map<String, JsonValue>,
    name: &str,
    j: JsonValue,
    on_err: Option<&str>,
    defv: Option<serde_yaml::Value>,
) -> Result<(), MappingError> {
    let on = on_err.unwrap_or("fail");
    if j.is_null() && on == "omit" {
        return Ok(());
    }
    if j.is_null() && on == "default" {
        if let Some(d) = defv {
            obj.insert(
                name.to_string(),
                serde_json::to_value(d).unwrap_or(JsonValue::Null),
            );
            return Ok(());
        }
    }
    obj.insert(name.to_string(), omit_null_keys(j));
    Ok(())
}

fn apply_field_error_output(
    obj: &mut Map<String, JsonValue>,
    name: &str,
    path: &str,
    on_err: &str,
    defv: Option<serde_yaml::Value>,
    err: impl Display,
    expr_source: &str,
) -> Result<(), MappingError> {
    match on_err {
        "fail" => Err(mapping_err_with_expr(
            ErrorCode::EvaluationError,
            err.to_string(),
            Some(path.to_string()),
            expr_source,
        )),
        "omit" => Ok(()),
        "default" => {
            if let Some(d) = defv {
                obj.insert(
                    name.to_string(),
                    serde_json::to_value(d).unwrap_or(JsonValue::Null),
                );
            }
            Ok(())
        }
        _ => {
            obj.insert(name.to_string(), JsonValue::Null);
            Ok(())
        }
    }
}

fn truthy_json(v: &JsonValue) -> bool {
    if matches!(v, JsonValue::String(s) if s == MISSING_STR) {
        return false;
    }
    match v {
        JsonValue::Bool(b) => *b,
        JsonValue::Null => false,
        JsonValue::Number(n) => n.as_i64() != Some(0) && n.as_u64() != Some(0),
        JsonValue::String(s) => !s.is_empty(),
        JsonValue::Array(items) => !items.is_empty(),
        JsonValue::Object(map) => !map.is_empty(),
    }
}

fn eval_compiled_json(
    cel: &CompiledCel,
    source: &JsonValue,
    root: &JsonValue,
    ctx: &JsonValue,
    vars: JsonValue,
    item: Option<&JsonValue>,
    index: Option<i64>,
    as_name: Option<&str>,
    limits: &SecurityLimits,
    codes: &Arc<crate::code_system::CodeSystemRegistry>,
) -> Result<JsonValue, String> {
    let mut root_bindings = BTreeMap::from([
        ("source".to_string(), source.clone()),
        ("root".to_string(), root.clone()),
        ("ctx".to_string(), ctx.clone()),
        ("vars".to_string(), vars),
    ]);
    if let Some(index) = index {
        root_bindings.insert("index".to_string(), JsonValue::from(index));
    }
    if let (Some(item), Some(as_name)) = (item, as_name) {
        root_bindings.insert(as_name.to_string(), item.clone());
        if as_name != "item" {
            root_bindings.insert("item".to_string(), item.clone());
        }
    } else {
        root_bindings.insert("item".to_string(), JsonValue::Null);
    }
    crosswalk_cel::evaluate_compiled_expression_with_input_and_limits(
        cel,
        StandaloneExpressionInput::new(root_bindings),
        limits,
        Arc::clone(codes),
    )
    .map_err(|err| err.to_string())
}

/// `path_suffix` is the last segment after `records.{record}.` (e.g. `fields.foo`, `when`, `vars.x`).
fn exec_validation_err(path: &str, expr: &str, message: &str, e: impl Display) -> MappingError {
    mapping_err_with_expr(
        ErrorCode::EvaluationError,
        format!("{message}: {}", e),
        Some(path.to_string()),
        expr,
    )
}

fn mapping_err_with_expr(
    code: ErrorCode,
    message: impl Into<String>,
    path: Option<String>,
    expr_source: &str,
) -> MappingError {
    let mut err = MappingError::error(code, message, path, Some(expr_source.to_string()));
    err.source_path = crate::paths::primary_binding_hint(expr_source);
    err
}

fn exec_mapping_err_path(
    record: &str,
    field: &str,
    e: impl Display,
    path_suffix: &str,
    expr_source: &str,
) -> MappingError {
    let path =
        if path_suffix.starts_with("vars.") || matches!(path_suffix, "when" | "emit" | "foreach") {
            format!("records.{record}.{path_suffix}")
        } else {
            format!("records.{record}.fields.{field}")
        };
    mapping_err_with_expr(
        ErrorCode::EvaluationError,
        e.to_string(),
        Some(path),
        expr_source,
    )
    .with_record(record.to_string(), None)
}

/// Evaluate one mapping-stdlib CEL expression (no YAML mapping document).
///
/// Bindings match field expressions: `source`, `root`, `ctx`, `vars` (empty object), `item` (null).
/// Dotted paths in the expression are scanned so the binding envelope can inject Missing placeholders
/// under `source` / `root` / `ctx` like full mappings.
pub fn evaluate_cel_expression(
    expr: &str,
    source: JsonValue,
    ctx: JsonValue,
    limits: &crate::security::SecurityLimits,
    codes: Arc<crate::code_system::CodeSystemRegistry>,
) -> Result<JsonValue, StandaloneEvalError> {
    crosswalk_cel::evaluate_cel_expression(expr, source, ctx, limits, codes)
}

/// Evaluate one mapping-stdlib CEL expression against arbitrary root bindings.
///
/// Binding names must be valid CEL-style identifiers. Dotted paths used only in missing-aware
/// helper arguments receive the same Missing sentinel treatment as full mappings.
pub fn evaluate_cel_expression_with_input(
    expr: &str,
    input: StandaloneExpressionInput,
    limits: &crate::security::SecurityLimits,
    codes: Arc<crate::code_system::CodeSystemRegistry>,
) -> Result<JsonValue, StandaloneEvalError> {
    crosswalk_cel::evaluate_cel_expression_with_input(expr, input, limits, codes)
}

/// Compile and evaluate one expression, returning **structured** diagnostics (syntax line/column,
/// evaluation messages) plus an optional JSON value — intended for editors and playgrounds.
pub fn preview_cel_expression(
    expr: &str,
    source: JsonValue,
    ctx: JsonValue,
    limits: &crate::security::SecurityLimits,
    codes: Arc<crate::code_system::CodeSystemRegistry>,
) -> ExpressionPreviewResult {
    crosswalk_cel::preview_cel_expression(expr, source, ctx, limits, codes)
}

/// Compile and evaluate one expression against arbitrary root bindings, returning structured
/// diagnostics instead of `Err`.
pub fn preview_cel_expression_with_input(
    expr: &str,
    input: StandaloneExpressionInput,
    limits: &crate::security::SecurityLimits,
    codes: Arc<crate::code_system::CodeSystemRegistry>,
) -> ExpressionPreviewResult {
    crosswalk_cel::preview_cel_expression_with_input(expr, input, limits, codes)
}

pub fn validate_root_binding_name(name: &str) -> Result<(), String> {
    crosswalk_cel::validate_root_binding_name(name)
}
