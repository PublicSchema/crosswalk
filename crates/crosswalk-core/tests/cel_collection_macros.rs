//! End-to-end regression suite for CEL collection macros through MappingRuntime.
//!
//! Exercises the exact patterns the DHIS2 health-programme port (WS1) requires,
//! using a synthetic but realistic tracker-entity JSON fixture that mirrors the
//! fields fetched by dhis2-health-lookup.js.
//!
//! Run: `cargo test -p crosswalk-core --test cel_collection_macros`

use crosswalk_core::runtime::{EvaluationInput, MappingRuntime, RuntimeOptions};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn load_fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn source() -> Value {
    serde_json::from_str(&load_fixture("dhis2_tracked_entity.json"))
        .expect("parse dhis2_tracked_entity.json")
}

fn mapping_yaml() -> String {
    load_fixture("dhis2_health_mapping.yaml")
}

// ---------------------------------------------------------------------------
// Helper: compile & evaluate the DHIS2 mapping against the standard fixture,
// assert no mapping errors, and return the first (and only) `patient` row.
// ---------------------------------------------------------------------------
fn patient_row() -> Value {
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let compiled = rt
        .compile_mapping(&mapping_yaml())
        .expect("mapping should compile");

    let out = rt.evaluate(
        &compiled,
        EvaluationInput {
            source: source(),
            context: json!({}),
        },
    );

    assert!(
        out.errors.is_empty(),
        "unexpected mapping errors: {:#?}",
        out.errors
    );

    let rows = out
        .records
        .get("patient")
        .expect("patient record should be present");
    assert_eq!(rows.len(), 1, "expected exactly one patient row");
    rows[0].clone()
}

// ===========================================================================
// DHIS2 pattern tests — each assertion is independently documented
// ===========================================================================

/// Pattern 1a — `filter([0]).value`: attribute lookup by attribute-id.
/// Mirrors JS: `attributes.find(a => a.attribute === FIRST_NAME_ATTRIBUTE)?.value`
#[test]
fn first_name_extracted_via_filter_and_index() {
    let row = patient_row();
    assert_eq!(
        row["first_name"],
        json!("Alice"),
        "first_name should be extracted from attributes array by filter+[0].value"
    );
}

/// Pattern 1b — same shape, different attribute id.
#[test]
fn last_name_extracted_via_filter_and_index() {
    let row = patient_row();
    assert_eq!(
        row["last_name"],
        json!("Nakato"),
        "last_name should be extracted from attributes array by filter+[0].value"
    );
}

/// Pattern 2a — `exists(e, e.program == X && e.status == 'ACTIVE')`.
/// Child programme is ACTIVE in the fixture — should be true.
#[test]
fn child_program_active_true_when_enrolled_and_active() {
    let row = patient_row();
    assert_eq!(
        row["child_program_active"],
        json!(true),
        "child_program_active: ACTIVE child enrollment should yield true"
    );
}

/// Pattern 2b — programme absent in fixture → exists returns false.
/// The synthetic fixture has no maternal-PNC enrollment at all.
#[test]
fn maternal_pnc_active_false_when_not_enrolled() {
    let row = patient_row();
    assert_eq!(
        row["maternal_pnc_active"],
        json!(false),
        "maternal_pnc_active: no maternal PNC enrollment in fixture → false"
    );
}

/// Pattern 2c — TB programme is enrolled but status is COMPLETED, not ACTIVE.
#[test]
fn tb_program_active_false_when_status_is_completed() {
    let row = patient_row();
    assert_eq!(
        row["tb_program_active"],
        json!(false),
        "tb_program_active: TB enrollment exists but status=COMPLETED → false"
    );
}

/// Pattern 3a — `filter([0]).status` guarded by ternary.
/// Child programme is present in fixture with status="ACTIVE".
#[test]
fn child_program_status_when_enrolled() {
    let row = patient_row();
    assert_eq!(
        row["child_program_status"],
        json!("ACTIVE"),
        "child_program_status should be 'ACTIVE' from filter+[0].status"
    );
}

/// Pattern 3b — TB programme is present, status="COMPLETED".
#[test]
fn tb_program_status_when_enrolled_but_completed() {
    let row = patient_row();
    assert_eq!(
        row["tb_program_status"],
        json!("COMPLETED"),
        "tb_program_status should be 'COMPLETED'"
    );
}

/// Pattern 4 — `size(enrollments.filter(e, e.status == 'ACTIVE'))`.
/// The fixture has 1 ACTIVE enrollment (child) and 1 COMPLETED (TB).
#[test]
fn active_enrollment_count_is_one() {
    let row = patient_row();
    assert_eq!(
        row["active_enrollment_count"],
        json!(1),
        "active_enrollment_count: only the child enrollment is ACTIVE"
    );
}

/// Pattern 5 — nested `exists` over events with compound predicate.
/// Child programme has events with programStage in {A03MvHHogjR, ZzYYXq4fJie}
/// and status=COMPLETED — so child_health_visit_recorded should be true.
#[test]
fn child_health_visit_recorded_true_when_completed_stage_exists() {
    let row = patient_row();
    assert_eq!(
        row["child_health_visit_recorded"],
        json!(true),
        "child_health_visit_recorded: completed child-health stage events exist → true"
    );
}

/// Pattern 6 — flatMap-equivalent: `size(list_flatten(...map...).filter(...))`.
///
/// Fixture: child programme has 3 events — ev-001 (COMPLETED), ev-002 (COMPLETED),
/// ev-003 (ACTIVE). Only COMPLETED ones are counted → expected 2.
///
/// CEL expression:
///   size(list_flatten(
///     source.enrollments.filter(e, e.program == 'IpHINAT79UW').map(e, e.events)
///   ).filter(ev, ev.status == 'COMPLETED'))
///
/// This replicates the JS `flatMap` idiom using native `map` + crosswalk `list_flatten`.
#[test]
fn child_health_visit_count_via_flatmap_equivalent() {
    let row = patient_row();
    assert_eq!(
        row["child_health_visit_count"],
        json!(2),
        "child_health_visit_count: 2 COMPLETED events in child enrolment (of 3 total)"
    );
}

/// Pattern 7 — string concatenation for reconciliation reference.
/// Mirrors JS: `TRACKED_ENTITY_REF_PREFIX + trackedEntity.trackedEntity`
#[test]
fn reconciliation_ref_is_prefixed_entity_id() {
    let row = patient_row();
    assert_eq!(
        row["reconciliation_ref"],
        json!("dhis2:tracked-entity:F8yKM85NbxW"),
        "reconciliation_ref should be 'dhis2:tracked-entity:' + trackedEntity value"
    );
}

// ===========================================================================
// Inline mapping tests — verify individual CEL constructs without the fixture file
// ===========================================================================

/// Verify filter+index pattern works on a minimal inline fixture.
#[test]
fn inline_filter_index_field_access() {
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      name: "source.attrs.filter(a, a.id == 'x')[0].val"
"#;
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let compiled = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &compiled,
        EvaluationInput {
            source: json!({"attrs": [{"id": "y", "val": "no"}, {"id": "x", "val": "yes"}]}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:#?}", out.errors);
    assert_eq!(out.records["r"][0]["name"], json!("yes"));
}

/// Verify exists with && compound predicate inline.
#[test]
fn inline_exists_compound_and() {
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      active: "source.enrls.exists(e, e.prog == 'P1' && e.status == 'ACTIVE')"
"#;
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let compiled = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &compiled,
        EvaluationInput {
            source: json!({"enrls": [
                {"prog": "P1", "status": "ACTIVE"},
                {"prog": "P2", "status": "ACTIVE"}
            ]}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:#?}", out.errors);
    assert_eq!(out.records["r"][0]["active"], json!(true));
}

/// Verify list_length(filter()) inline.
/// `list_length()` is used here for explicitness; `.size()` and `size(...)`
/// over a comprehension result work equally well.
#[test]
fn inline_size_of_filter_via_list_length() {
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      count: "list_length(source.items.filter(x, int(x) > 3))"
"#;
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let compiled = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &compiled,
        EvaluationInput {
            source: json!({"items": [1, 2, 3, 4, 5]}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:#?}", out.errors);
    assert_eq!(out.records["r"][0]["count"], json!(2));
}

/// Verify the flatMap pattern (map + list_flatten + filter + list_length) inline.
/// `list_length()` is used for the count; `.size()` / `size(...)` work equally.
#[test]
fn inline_flatmap_via_map_list_flatten_filter_size() {
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      completed: >-
        list_length(list_flatten(source.groups.map(g, g.items)).filter(i, i.done == true))
"#;
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let compiled = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &compiled,
        EvaluationInput {
            source: json!({"groups": [
                {"items": [{"done": true}, {"done": false}]},
                {"items": [{"done": true}, {"done": true}]}
            ]}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:#?}", out.errors);
    assert_eq!(out.records["r"][0]["completed"], json!(3));
}

/// Verify nested exists (outer loop → inner loop) inline.
#[test]
fn inline_nested_exists() {
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      found: >-
        source.outer.exists(o, o.inner.exists(i, i.val == 42u))
"#;
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let compiled = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &compiled,
        EvaluationInput {
            source: json!({"outer": [
                {"inner": [{"val": 1}, {"val": 2}]},
                {"inner": [{"val": 42}]}
            ]}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:#?}", out.errors);
    assert_eq!(out.records["r"][0]["found"], json!(true));
}

/// Verify string concat for reconciliation_ref inline.
#[test]
fn inline_string_concat_reconciliation_ref() {
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      ref: "'dhis2:tracked-entity:' + source.id"
"#;
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let compiled = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &compiled,
        EvaluationInput {
            source: json!({"id": "ABC123"}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:#?}", out.errors);
    assert_eq!(
        out.records["r"][0]["ref"],
        json!("dhis2:tracked-entity:ABC123")
    );
}

/// Vacuous-truth: all() over empty list is true.
#[test]
fn inline_all_vacuous_truth_on_empty() {
    let yaml = r#"
version: "0.1"
name: t
records:
  r:
    fields:
      v: "source.items.all(x, x > 0)"
"#;
    let rt = MappingRuntime::new(RuntimeOptions::default());
    let compiled = rt.compile_mapping(yaml).unwrap();
    let out = rt.evaluate(
        &compiled,
        EvaluationInput {
            source: json!({"items": []}),
            context: json!({}),
        },
    );
    assert!(out.errors.is_empty(), "{:#?}", out.errors);
    assert_eq!(out.records["r"][0]["v"], json!(true));
}
