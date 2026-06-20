//! Regression tests for spec-critical behaviour (review feedback P1/P2).

use crosswalk_core::compiled::ErrorMode;
use crosswalk_core::expr::rewrite_namespaced_calls;
use crosswalk_core::output::JSON_SAFE_INT_MAX;
use crosswalk_core::paths::{build_binding_envelope, collect_dotted_paths};
use crosswalk_core::runtime::{EvaluationInput, MappingRuntime, RuntimeOptions};
use crosswalk_core::security::SecurityLimits;
use crosswalk_core::CompileError;
use crosswalk_core::ExpressionPhase;
use crosswalk_core::StandaloneEvalError;
use serde_json::json;

#[test]
fn rewrite_namespaced_skips_string_literals() {
    let e = r#"map.get(source, "person.name")"#;
    assert_eq!(
        rewrite_namespaced_calls(e),
        r#"map_get(source, "person.name")"#
    );
}

#[test]
fn binding_envelope_injects_missing_under_source() {
    let paths = collect_dotted_paths(&["present(source.missing_field)".to_string()]);
    let source = json!({"other": 1});
    let ctx = json!({});
    let (s, _, _) = build_binding_envelope(source, ctx, &paths, "__MISSING__");
    assert_eq!(s["missing_field"], "__MISSING__");
    assert_eq!(s["other"], json!(1));
}

#[test]
fn custom_foreach_alias_gets_missing_injection() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
errors:
  mode: collect
records:
  children:
    foreach: "source.children"
    as: child
    when: "present(child.name)"
    fields:
      name: "child.name"
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({ "children": [{}] }),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert_eq!(out.records["children"].len(), 0);
}

#[test]
fn vars_evaluate_in_yaml_order() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    vars:
      z_first: '"ok"'
      a_second: "vars.z_first"
    fields:
      x: "vars.a_second"
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert_eq!(out.records["r"][0]["x"], json!("ok"));
}

#[test]
fn collect_mode_required_missing_suppresses_row() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
errors:
  mode: collect
records:
  r:
    fields:
      x:
        expr: "source.missing"
        required: true
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(!out.errors.is_empty());
    assert_eq!(out.records["r"].len(), 0);
}

#[test]
fn public_evaluation_rejects_js_unsafe_integer_output() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let result = rt.evaluate_cel_expression(
        &(JSON_SAFE_INT_MAX + 1).to_string(),
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );

    assert!(matches!(result, Err(StandaloneEvalError::Evaluate { .. })));
}

#[test]
fn strict_mode_fails_optional_field_on_eval_error_by_default() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
errors:
  mode: strict
records:
  r:
    fields:
      x: 'type_int("not_a_number")'
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(
        !out.errors.is_empty(),
        "strict + default on_error should surface field errors, got {:?}",
        out.errors
    );
    assert!(out.records.get("r").map(|v| v.is_empty()).unwrap_or(true));
}

#[test]
fn collect_mode_records_field_error_and_emits_partial_row() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
errors:
  mode: collect
records:
  r:
    fields:
      ok: 'type_string(1)'
      x: 'type_int("bad")'
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(!out.errors.is_empty());
    let rows = out.records.get("r").expect("record r");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["ok"], json!("1"));
    assert!(rows[0].get("x").map(|v| v.is_null()).unwrap_or(false));
}

#[test]
fn runtime_default_errors_mode_used_when_yaml_omits_errors_mode() {
    let rt = MappingRuntime::new(RuntimeOptions {
        default_errors_mode: Some("collect".into()),
        ..Default::default()
    });
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      ok: '"hello"'
      bad: 'type_int("not_a_number")'
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    assert_eq!(m.error_mode, ErrorMode::Collect);
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(!out.errors.is_empty());
    let rows = out.records.get("r").expect("record r");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["ok"], json!("hello"));
    assert!(rows[0].get("bad").map(|v| v.is_null()).unwrap_or(false));
}

#[test]
fn yaml_errors_mode_overrides_runtime_default_errors_mode() {
    let rt = MappingRuntime::new(RuntimeOptions {
        default_errors_mode: Some("collect".into()),
        ..Default::default()
    });
    let yaml = r#"
version: "0.1"
name: t
errors:
  mode: strict
records:
  r:
    fields:
      x: 'type_int("bad")'
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    assert_eq!(m.error_mode, ErrorMode::Strict);
}

#[test]
fn lenient_mode_optional_eval_error_is_warning_and_emits_null_field() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
errors:
  mode: lenient
records:
  r:
    fields:
      ok: 'type_string(1)'
      x: 'type_int("bad")'
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(
        out.errors.is_empty(),
        "lenient should not put optional field eval errors in errors: {:?}",
        out.errors
    );
    assert!(
        !out.warnings.is_empty(),
        "expected warnings, got {:?}",
        out.warnings
    );
    let rows = out.records.get("r").expect("record r");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["ok"], json!("1"));
    assert!(rows[0].get("x").map(|v| v.is_null()).unwrap_or(false));
}

#[test]
fn lenient_mode_optional_explicit_on_error_fail_still_emits_row_with_null() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
errors:
  mode: lenient
records:
  r:
    fields:
      ok: '"yes"'
      x:
        expr: 'type_int("bad")'
        required: false
        on_error: fail
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert!(!out.warnings.is_empty());
    let rows = out.records.get("r").expect("record r");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["ok"], json!("yes"));
    assert!(rows[0].get("x").map(|v| v.is_null()).unwrap_or(false));
}

#[test]
fn lenient_mode_validation_failure_is_warning() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
errors:
  mode: lenient
records:
  r:
    fields:
      ok: '"yes"'
validations:
  - expr: "false"
    message: "must be true"
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert!(
        out.warnings
            .iter()
            .any(|w| w.message.contains("must be true")),
        "expected validation warning, got {:?}",
        out.warnings
    );
    assert_eq!(out.records["r"][0]["ok"], json!("yes"));
}

#[test]
fn phone_normalize_uses_libphonenumber() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      p: 'phone_normalize("(650) 253-0000", "US")'
      cc: 'phone_country_code("+16502530000", "US")'
      ok: 'phone_is_valid("+16502530000", "US")'
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let row = &out.records["r"][0];
    assert_eq!(row["p"], json!("+16502530000"));
    assert_eq!(row["cc"], json!("1"));
    assert_eq!(row["ok"], json!(true));
}

#[test]
fn output_records_size_limit_enforced() {
    let mut rt = MappingRuntime::new(RuntimeOptions::default());
    rt.limits = SecurityLimits {
        max_expression_bytes: 256 * 1024,
        max_output_json_bytes: 80,
        max_list_len: 100_000,
        max_string_bytes: 1024 * 1024,
        max_eval_steps: 1_000_000,
    };
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      blob: '"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(
        out.errors
            .iter()
            .any(|e| e.message.contains("mapping output exceeds")),
        "expected output limit error, got {:?}",
        out.errors
    );
    assert!(out.records.is_empty() || out.records.get("r").map(|v| v.is_empty()).unwrap_or(true));
}

#[test]
fn mapping_evaluation_rejects_oversized_cel_input() {
    let mut rt = MappingRuntime::new(RuntimeOptions::default());
    rt.limits = SecurityLimits {
        max_expression_bytes: 256 * 1024,
        max_output_json_bytes: 64,
        max_list_len: 100_000,
        max_string_bytes: 1024 * 1024,
        max_eval_steps: 1_000_000,
    };
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      blob: source.blob
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({ "blob": "x".repeat(4096) }),
            context: json!({}),
        },
    );
    assert!(
        out.errors
            .iter()
            .any(|e| e.message.contains("input exceeds max")),
        "expected input limit error, got {:?}",
        out.errors
    );
}

#[test]
fn date_add_months_jan_31_clamps_to_feb_end() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      d: 'date_add_months("2024-01-31", 1)'
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let rows = out.records.get("r").unwrap();
    assert_eq!(rows[0]["d"], json!("2024-02-29"));
}

#[test]
fn date_parse_datetime_accepts_one_arg_rfc3339() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      ts: "date.parse_datetime('2024-01-15T10:30:00Z')"
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let ts = out.records["r"][0]["ts"].as_str().unwrap();
    assert!(ts.starts_with("2024-01-15T10:30:00"), "got {ts}");
}

#[test]
fn date_parse_datetime_two_arg_with_explicit_format() {
    let rt = MappingRuntime::new(RuntimeOptions {
        timezone: Some("Asia/Bangkok".into()),
        ..Default::default()
    });
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      ts: "date.parse_datetime('2024-01-15 10:30:00', 'yyyy-MM-dd HH:mm:ss')"
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let ts = out.records["r"][0]["ts"].as_str().unwrap();
    assert!(ts.starts_with("2024-01-15T10:30:00"), "got {ts}");
    assert!(ts.ends_with("+07:00"), "got {ts}");
}

#[test]
fn list_length_ignores_max_list_len_for_large_source_lists() {
    let mut rt = MappingRuntime::new(RuntimeOptions::default());
    rt.limits.max_list_len = 3;
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      n: "list_length(source.items)"
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let items: Vec<i32> = (0..20).collect();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({ "items": items }),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert_eq!(out.records["r"][0]["n"], json!(20));
}

#[test]
fn compile_error_includes_record_field_path_and_expression() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      x: "1 + + 2"
"#;
    let err = rt.compile_mapping(yaml).expect_err("invalid CEL");
    let text = err.to_string();
    assert!(
        text.contains("records.r.fields.x"),
        "expected path in error: {text}"
    );
    assert!(
        text.contains("1 + + 2"),
        "expected original expression in error: {text}"
    );
    let CompileError::Cel {
        path, expression, ..
    } = err
    else {
        panic!("expected CompileError::Cel, got {err:?}");
    };
    assert_eq!(path, "records.r.fields.x");
    assert_eq!(expression.trim(), "1 + + 2");
}

#[test]
fn evaluation_error_includes_field_expression() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let yaml = r#"
version: "0.1"
name: t
errors:
  mode: strict
records:
  r:
    fields:
      bad: 'type_int(source.x)'
"#;
    let m = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &m,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    let e = &out.errors[0];
    assert_eq!(
        e.expression.as_deref(),
        Some(r#"type_int(source.x)"#),
        "{e:?}"
    );
    assert_eq!(e.path.as_deref(), Some("records.r.fields.bad"), "{e:?}");
    assert_eq!(e.source_path.as_deref(), Some("source.x"), "{e:?}");
}

#[test]
fn evaluate_cel_expression_without_mapping_yaml() {
    let mut rt = MappingRuntime::new(RuntimeOptions::default());
    let cs = r#"
m:
  id: canon.m
  label:
    en: Male
"#;
    let v: serde_yaml::Value = serde_yaml::from_str(cs).unwrap();
    rt.register_code_system("demo.gender", &v).unwrap();

    let expr = r#"code.map_or_default('demo.gender', type_string(source.raw), 'canon.unknown')"#;
    let out = rt
        .evaluate_cel_expression(
            expr,
            EvaluationInput {
                source: json!({"raw": "m"}),
                context: json!({}),
            },
        )
        .unwrap();
    assert_eq!(out, json!("canon.m"));
}

#[test]
fn evaluate_cel_expression_compile_error_is_standalone_compile() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let err = rt
        .evaluate_cel_expression(
            "1 +",
            EvaluationInput {
                source: json!({}),
                context: json!({}),
            },
        )
        .unwrap_err();
    assert!(matches!(
        err,
        StandaloneEvalError::Compile(CompileError::Cel { .. })
    ));
}

#[test]
fn preview_expression_reports_syntax_line_column() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let r = rt.preview_cel_expression(
        "1 +",
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(!r.is_ok());
    assert_eq!(r.value, None);
    assert_eq!(r.author_expression, "1 +");
    assert_eq!(r.rewritten_expression.as_deref(), Some("1 +"));
    assert!(!r.notes.is_empty());
    assert_eq!(r.issues.len(), 1);
    let i = &r.issues[0];
    assert_eq!(i.phase, ExpressionPhase::Syntax);
    assert_eq!(i.line, Some(1));
    assert!(i.column.is_some(), "column: {:?}", i.column);
    assert!(
        i.message.contains("ERROR:") || i.message.contains('|'),
        "expected CEL formatter output in message: {:?}",
        i.message
    );
}

#[test]
fn preview_expression_success_matches_evaluate() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let prev = rt.preview_cel_expression(
        "type_string(1)",
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(prev.is_ok());
    assert_eq!(prev.author_expression, "type_string(1)");
    assert_eq!(prev.rewritten_expression.as_deref(), Some("type_string(1)"));
    assert_eq!(prev.value, Some(json!("1")));
    let ev = rt
        .evaluate_cel_expression(
            "type_string(1)",
            EvaluationInput {
                source: json!({}),
                context: json!({}),
            },
        )
        .unwrap();
    assert_eq!(prev.value.unwrap(), ev);
}

#[test]
fn preview_expression_limit_issue_has_limits_phase() {
    let mut rt = MappingRuntime::new(RuntimeOptions::default());
    rt.limits.max_expression_bytes = 4;
    let r = rt.preview_cel_expression(
        "1 + 2",
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert!(!r.is_ok());
    assert_eq!(r.author_expression, "1 + 2");
    assert!(r.rewritten_expression.is_none());
    assert!(r.notes.is_empty());
    assert_eq!(r.issues.len(), 1);
    assert_eq!(r.issues[0].phase, ExpressionPhase::Limits);
}

#[test]
fn preview_expression_rewritten_differs_when_namespaced() {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let author = r#"map.get(source, "k")"#;
    let r = rt.preview_cel_expression(
        author,
        EvaluationInput {
            source: json!({}),
            context: json!({}),
        },
    );
    assert_eq!(r.author_expression, author);
    let rw = r.rewritten_expression.as_deref().expect("rewritten");
    assert!(rw.contains("map_get"), "rewritten={rw:?}");
    assert_ne!(author, rw);
}
