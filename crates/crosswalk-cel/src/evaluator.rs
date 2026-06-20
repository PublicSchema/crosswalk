use crate::compiled::CompiledCel;
use crate::compiler::compile_expr;
use crate::errors::{
    ErrorCode, ExpressionIssue, ExpressionPhase, ExpressionPreviewResult, StandaloneEvalError,
};
use crate::missing::MISSING_STR;
use crate::output::cel_to_json;
use crate::paths::{augment_json_with_paths, collect_missing_aware_injection_paths};
use crate::security::SecurityLimits;
use cel::{Context, ExecutionError, Program, Value};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as JsonValue};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StandaloneExpressionInput {
    #[serde(default)]
    pub root_bindings: BTreeMap<String, JsonValue>,
}

impl StandaloneExpressionInput {
    pub fn new(root_bindings: BTreeMap<String, JsonValue>) -> Self {
        Self { root_bindings }
    }

    pub fn from_source_context(source: JsonValue, context: JsonValue) -> Self {
        let mut root_bindings = BTreeMap::new();
        root_bindings.insert("source".to_string(), source.clone());
        root_bindings.insert("root".to_string(), source);
        root_bindings.insert("ctx".to_string(), context);
        root_bindings.insert("vars".to_string(), JsonValue::Object(Map::new()));
        root_bindings.insert("item".to_string(), JsonValue::Null);
        Self { root_bindings }
    }
}

fn json_to_cel(value: &JsonValue) -> Value {
    cel::to_value(value).unwrap_or(Value::Null)
}

fn run_program_with_root_bindings(
    cel: &CompiledCel,
    root_bindings: &BTreeMap<String, Value>,
    extra_bindings: &[(&str, Value)],
    codes: &Arc<crosswalk_functions::codes::CodeSystemRegistry>,
) -> Result<Value, ExecutionError> {
    let mut context = Context::default();
    crosswalk_functions_cel::register_stdlib(&mut context, Arc::clone(codes));
    for (name, value) in root_bindings {
        context.add_variable_from_value(name.as_str(), value.clone());
    }
    for (name, value) in extra_bindings {
        context.add_variable_from_value(*name, value.clone());
    }
    cel.program.execute(&context)
}

pub fn evaluate_cel_expression(
    expr: &str,
    source: JsonValue,
    ctx: JsonValue,
    limits: &SecurityLimits,
    codes: Arc<crosswalk_functions::codes::CodeSystemRegistry>,
) -> Result<JsonValue, StandaloneEvalError> {
    evaluate_cel_expression_with_input(
        expr,
        StandaloneExpressionInput::from_source_context(source, ctx),
        limits,
        codes,
    )
}

pub fn evaluate_cel_expression_with_input(
    expr: &str,
    input: StandaloneExpressionInput,
    limits: &SecurityLimits,
    codes: Arc<crosswalk_functions::codes::CodeSystemRegistry>,
) -> Result<JsonValue, StandaloneEvalError> {
    // F1 (CPU-DoS): `cel` 0.13 has no per-step/fuel budget, so a crafted comprehension
    // (`.map`/`.filter`/`.exists`) over a large input list can run unbudgeted. Comprehension
    // iteration counts are bounded by input list sizes, so we bound the input itself here, before
    // compiling/executing, using `max_output_json_bytes` as a symmetric input ceiling. This is a
    // portable (incl. WASM) partial CPU-DoS bound that needs no threads/watchdog/timeout.
    check_input_size(&input.root_bindings, limits)?;
    let cel = compile_expr(expr, limits, "expression".into())?;
    evaluate_compiled_expression_with_prechecked_input(&cel, input, codes)
}

/// Reject input root bindings whose serialized JSON exceeds the symmetric input cap
/// (`limits.max_output_json_bytes`). See F1 above.
fn check_input_size(
    root_bindings: &BTreeMap<String, JsonValue>,
    limits: &SecurityLimits,
) -> Result<(), StandaloneEvalError> {
    let bytes = serde_json::to_string(root_bindings)
        .map(|s| s.len())
        .map_err(|err| StandaloneEvalError::Evaluate {
            message: format!("failed to measure input size: {err}"),
            expression: String::new(),
        })?;
    if bytes > limits.max_output_json_bytes {
        return Err(StandaloneEvalError::Evaluate {
            message: format!(
                "input exceeds max {} bytes (serialized root bindings are {} bytes)",
                limits.max_output_json_bytes, bytes
            ),
            expression: String::new(),
        });
    }
    Ok(())
}

pub fn evaluate_compiled_expression_with_input(
    cel: &CompiledCel,
    input: StandaloneExpressionInput,
    codes: Arc<crosswalk_functions::codes::CodeSystemRegistry>,
) -> Result<JsonValue, StandaloneEvalError> {
    evaluate_compiled_expression_with_input_and_limits(
        cel,
        input,
        &SecurityLimits::default(),
        codes,
    )
}

pub fn evaluate_compiled_expression_with_input_and_limits(
    cel: &CompiledCel,
    input: StandaloneExpressionInput,
    limits: &SecurityLimits,
    codes: Arc<crosswalk_functions::codes::CodeSystemRegistry>,
) -> Result<JsonValue, StandaloneEvalError> {
    check_input_size(&input.root_bindings, limits)?;
    evaluate_compiled_expression_with_prechecked_input(cel, input, codes)
}

fn evaluate_compiled_expression_with_prechecked_input(
    cel: &CompiledCel,
    input: StandaloneExpressionInput,
    codes: Arc<crosswalk_functions::codes::CodeSystemRegistry>,
) -> Result<JsonValue, StandaloneEvalError> {
    validate_root_bindings(&input.root_bindings)?;
    let paths = collect_missing_aware_injection_paths(&[&cel.program]);
    let root_bindings = prepare_root_bindings(input.root_bindings, &paths);
    let value =
        run_program_with_root_bindings(cel, &root_bindings, &[], &codes).map_err(|err| {
            StandaloneEvalError::Evaluate {
                message: err.to_string(),
                expression: cel.source.clone(),
            }
        })?;
    cel_to_json(&value).map_err(|message| StandaloneEvalError::Evaluate {
        message,
        expression: cel.source.clone(),
    })
}

const MAX_DIAGNOSTIC_CHARS: usize = 12_000;

fn issues_from_parse_errors(
    author_expression: &str,
    err: &cel::ParseErrors,
) -> Vec<ExpressionIssue> {
    err.errors
        .iter()
        .map(|parse_error| ExpressionIssue {
            phase: ExpressionPhase::Syntax,
            severity: crate::errors::ErrorSeverity::Error,
            code: ErrorCode::ParseError,
            message: crate::errors::truncate_diagnostic_string(
                &parse_error.to_string(),
                MAX_DIAGNOSTIC_CHARS,
            ),
            line: isize_pos_to_u32(parse_error.pos.0),
            column: isize_pos_to_u32(parse_error.pos.1),
            expression: author_expression.to_string(),
            source_path: None,
        })
        .collect()
}

fn isize_pos_to_u32(value: isize) -> Option<u32> {
    if value <= 0 {
        None
    } else {
        Some(value as u32)
    }
}

pub fn preview_cel_expression(
    expr: &str,
    source: JsonValue,
    ctx: JsonValue,
    limits: &SecurityLimits,
    codes: Arc<crosswalk_functions::codes::CodeSystemRegistry>,
) -> ExpressionPreviewResult {
    preview_cel_expression_with_input(
        expr,
        StandaloneExpressionInput::from_source_context(source, ctx),
        limits,
        codes,
    )
}

pub fn preview_cel_expression_with_input(
    expr: &str,
    input: StandaloneExpressionInput,
    limits: &SecurityLimits,
    codes: Arc<crosswalk_functions::codes::CodeSystemRegistry>,
) -> ExpressionPreviewResult {
    let author = expr.to_string();

    if let Err(issue) = validate_root_bindings_for_preview(&input.root_bindings, &author) {
        return ExpressionPreviewResult::from_parts(author, None, vec![issue]);
    }

    if let Err(issue) = validate_input_size_for_preview(&input.root_bindings, limits, &author) {
        return ExpressionPreviewResult::from_parts(author, None, vec![issue]);
    }

    if let Err(message) = limits.check_expr(expr) {
        return ExpressionPreviewResult::from_parts(
            author.clone(),
            None,
            vec![ExpressionIssue {
                phase: ExpressionPhase::Limits,
                severity: crate::errors::ErrorSeverity::Error,
                code: ErrorCode::InternalError,
                message,
                line: None,
                column: None,
                expression: author.clone(),
                source_path: None,
            }],
        );
    }

    let rewritten = crate::expr::rewrite_namespaced_calls(expr);
    let cel = match Program::compile(&rewritten) {
        Ok(program) => CompiledCel {
            program,
            source: author.clone(),
        },
        Err(err) => {
            return ExpressionPreviewResult::from_parts(
                author.clone(),
                Some(rewritten.clone()),
                issues_from_parse_errors(&author, &err),
            )
        }
    };

    let paths = collect_missing_aware_injection_paths(&[&cel.program]);
    let root_bindings = prepare_root_bindings(input.root_bindings, &paths);

    let value = match run_program_with_root_bindings(&cel, &root_bindings, &[], &codes) {
        Ok(value) => value,
        Err(err) => {
            return ExpressionPreviewResult::from_parts(
                author.clone(),
                Some(rewritten.clone()),
                vec![ExpressionIssue {
                    phase: ExpressionPhase::Evaluation,
                    severity: crate::errors::ErrorSeverity::Error,
                    code: ErrorCode::EvaluationError,
                    message: crate::errors::truncate_diagnostic_string(
                        &err.to_string(),
                        MAX_DIAGNOSTIC_CHARS,
                    ),
                    line: None,
                    column: None,
                    expression: cel.source.clone(),
                    source_path: crate::paths::primary_binding_hint(&cel.source),
                }],
            )
        }
    };

    match cel_to_json(&value) {
        Ok(json) => ExpressionPreviewResult::success(author, rewritten, json),
        Err(message) => ExpressionPreviewResult::from_parts(
            author.clone(),
            Some(rewritten.clone()),
            vec![ExpressionIssue {
                phase: ExpressionPhase::Evaluation,
                severity: crate::errors::ErrorSeverity::Error,
                code: ErrorCode::TypeError,
                message,
                line: None,
                column: None,
                expression: cel.source.clone(),
                source_path: crate::paths::primary_binding_hint(&cel.source),
            }],
        ),
    }
}

fn prepare_root_bindings(
    root_bindings: BTreeMap<String, JsonValue>,
    paths: &[(String, Vec<String>)],
) -> BTreeMap<String, Value> {
    let mut env = JsonValue::Object(root_bindings.into_iter().collect());
    augment_json_with_paths(&mut env, paths, MISSING_STR);
    match env {
        JsonValue::Object(map) => map
            .into_iter()
            .map(|(key, value)| (key, json_to_cel(&value)))
            .collect(),
        _ => BTreeMap::new(),
    }
}

fn validate_root_bindings(
    root_bindings: &BTreeMap<String, JsonValue>,
) -> Result<(), StandaloneEvalError> {
    for name in root_bindings.keys() {
        if let Err(message) = validate_root_binding_name(name) {
            return Err(StandaloneEvalError::InvalidBindingName {
                name: name.clone(),
                message,
            });
        }
    }
    Ok(())
}

fn validate_root_bindings_for_preview(
    root_bindings: &BTreeMap<String, JsonValue>,
    expression: &str,
) -> Result<(), ExpressionIssue> {
    for name in root_bindings.keys() {
        if let Err(message) = validate_root_binding_name(name) {
            return Err(ExpressionIssue {
                phase: ExpressionPhase::Evaluation,
                severity: crate::errors::ErrorSeverity::Error,
                code: ErrorCode::EvaluationError,
                message: format!("invalid root binding name `{name}`: {message}"),
                line: None,
                column: None,
                expression: expression.to_string(),
                source_path: None,
            });
        }
    }
    Ok(())
}

fn validate_input_size_for_preview(
    root_bindings: &BTreeMap<String, JsonValue>,
    limits: &SecurityLimits,
    expression: &str,
) -> Result<(), ExpressionIssue> {
    check_input_size(root_bindings, limits).map_err(|err| ExpressionIssue {
        phase: ExpressionPhase::Limits,
        severity: crate::errors::ErrorSeverity::Error,
        code: ErrorCode::InternalError,
        message: err.to_string(),
        line: None,
        column: None,
        expression: expression.to_string(),
        source_path: None,
    })
}

pub fn validate_root_binding_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name must not be empty".to_string());
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err("name must not be empty".to_string());
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err("name must start with an ASCII letter or underscore".to_string());
    }
    if !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return Err("name may only contain ASCII letters, digits, and underscores".to_string());
    }
    if matches!(name, "true" | "false" | "null" | "in") {
        return Err("name is reserved by CEL".to_string());
    }
    Ok(())
}
