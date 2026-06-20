use crosswalk_cel::{
    compile_expr, evaluate_cel_expression, evaluate_cel_expression_with_input,
    evaluate_compiled_expression_with_input, preview_cel_expression_with_input, SecurityLimits,
    StandaloneEvalError, StandaloneExpressionInput,
};
use crosswalk_functions::codes::CodeSystemRegistry;
use serde_json::{json, Value as JsonValue};
use std::collections::BTreeMap;
use std::sync::Arc;

fn input(
    bindings: impl IntoIterator<Item = (&'static str, JsonValue)>,
) -> StandaloneExpressionInput {
    StandaloneExpressionInput::new(
        bindings
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect(),
    )
}

fn codes() -> Arc<CodeSystemRegistry> {
    Arc::new(CodeSystemRegistry::new())
}

#[test]
fn evaluates_arbitrary_root_bindings() {
    let result = evaluate_cel_expression_with_input(
        r#"patient.name + " @ " + encounter.id"#,
        input([
            ("patient", json!({ "name": "Asha" })),
            ("encounter", json!({ "id": "E-42" })),
        ]),
        &SecurityLimits::default(),
        codes(),
    )
    .unwrap();

    assert_eq!(result, json!("Asha @ E-42"));
}

#[test]
fn free_function_evaluates_arbitrary_root_bindings() {
    let result = evaluate_cel_expression_with_input(
        "claim.total + payment.amount",
        input([
            ("claim", json!({ "total": 7 })),
            ("payment", json!({ "amount": 5 })),
        ]),
        &SecurityLimits::default(),
        codes(),
    )
    .unwrap();

    assert_eq!(result, json!(12));
}

#[test]
fn missing_aware_helpers_work_for_arbitrary_roots() {
    assert_eq!(
        evaluate_cel_expression_with_input(
            "present(patient.middle_name)",
            input([("patient", json!({ "given_name": "Asha" }))]),
            &SecurityLimits::default(),
            codes(),
        )
        .unwrap(),
        json!(false)
    );
    assert_eq!(
        evaluate_cel_expression_with_input(
            r#"default(patient.middle_name, "N/A")"#,
            input([("patient", json!({ "given_name": "Asha" }))]),
            &SecurityLimits::default(),
            codes(),
        )
        .unwrap(),
        json!("N/A")
    );
}

#[test]
fn strict_access_for_arbitrary_root_missing_field_still_errors() {
    let result = evaluate_cel_expression_with_input(
        r#"patient.middle_name == "x""#,
        input([("patient", json!({ "given_name": "Asha" }))]),
        &SecurityLimits::default(),
        codes(),
    );

    assert!(
        result.is_err(),
        "strict missing access should not receive a Missing sentinel: {result:?}"
    );
}

#[test]
fn preview_evaluates_arbitrary_root_bindings() {
    let preview = preview_cel_expression_with_input(
        r#"default(patient.middle_name, "N/A")"#,
        input([("patient", json!({ "given_name": "Asha" }))]),
        &SecurityLimits::default(),
        codes(),
    );

    assert!(preview.is_ok(), "{:?}", preview.issues);
    assert_eq!(preview.value, Some(json!("N/A")));
}

#[test]
fn explicit_ctx_binding_is_available() {
    let result = evaluate_cel_expression_with_input(
        "ctx.timezone",
        input([("ctx", json!({"timezone": "Asia/Bangkok"}))]),
        &SecurityLimits::default(),
        codes(),
    )
    .unwrap();

    assert_eq!(result, json!("Asia/Bangkok"));
}

#[test]
fn evaluates_compiled_expression_with_json_bindings() {
    let limits = SecurityLimits::default();
    let compiled = compile_expr(
        r#"target.name + " / " + default(profile.nickname, "N/A")"#,
        &limits,
        "test.expression".into(),
    )
    .unwrap();

    let result = evaluate_compiled_expression_with_input(
        &compiled,
        input([("target", json!({ "name": "Ada" })), ("profile", json!({}))]),
        codes(),
    )
    .unwrap();

    assert_eq!(result, json!("Ada / N/A"));
}

#[test]
fn invalid_binding_names_are_rejected_for_evaluate_and_preview() {
    let mut root_bindings = BTreeMap::new();
    root_bindings.insert("bad-name".to_string(), json!({}));
    let input = StandaloneExpressionInput::new(root_bindings);

    let result =
        evaluate_cel_expression_with_input("1", input.clone(), &SecurityLimits::default(), codes());
    assert!(matches!(
        result,
        Err(StandaloneEvalError::InvalidBindingName { name, .. }) if name == "bad-name"
    ));

    let preview =
        preview_cel_expression_with_input("1", input, &SecurityLimits::default(), codes());
    assert!(!preview.is_ok());
    assert!(preview.issues[0]
        .message
        .contains("invalid root binding name `bad-name`"));
}

// F1 (CPU-DoS): inputs are bounded by `max_output_json_bytes` before compile/execute, so a crafted
// comprehension cannot iterate over an unboundedly large input list.
#[test]
fn oversized_input_is_rejected_by_evaluate_cel_expression() {
    // A small symmetric input cap; the `source` value below serializes well past it.
    let limits = SecurityLimits {
        max_output_json_bytes: 64,
        ..SecurityLimits::default()
    };
    let big_source = json!({ "blob": "x".repeat(4096) });

    let result = evaluate_cel_expression("source.blob", big_source, json!({}), &limits, codes());

    match result {
        Err(StandaloneEvalError::Evaluate { message, .. }) => {
            assert!(
                message.contains("input exceeds max"),
                "unexpected message: {message}"
            );
        }
        other => panic!("expected oversized-input rejection, got {other:?}"),
    }
}

#[test]
fn small_input_still_evaluates_with_small_cap() {
    let limits = SecurityLimits {
        max_output_json_bytes: 128,
        ..SecurityLimits::default()
    };
    // Tiny source/ctx stay well under the 128-byte cap.
    let result = evaluate_cel_expression(
        r#"source.name + "!""#,
        json!({ "name": "ok" }),
        json!({}),
        &limits,
        codes(),
    )
    .unwrap();
    assert_eq!(result, json!("ok!"));
}
