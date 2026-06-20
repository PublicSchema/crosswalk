//! PublicSchema-native mapping runtime (spec v0.2).
//!
//! This crate owns PublicSchema property-mapping parsing, compilation,
//! direction selection, JSON Pointer reads and writes, value mappings,
//! canonical hashes, transformation logs, and privacy-aware diagnostics. It
//! depends on `crosswalk-cel` for expression execution and `crosswalk-functions`
//! for code-system data, but not on the `crosswalk-core` facade.

use crosswalk_cel::SecurityLimits;
use crosswalk_cel::StandaloneExpressionInput;
use crosswalk_cel::{compile_expr, evaluate_compiled_expression_with_input_and_limits};
use crosswalk_cel::{CompileError, CompiledCel, ErrorMode};
use crosswalk_cel::{ErrorCode, ErrorSeverity, ExpressionPreviewResult, MappingError};
use crosswalk_functions::codes::{CodeEntry, CodeSystemDocument, CodeSystemRegistry};
use crosswalk_functions::FunctionError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Maximum size (in bytes) of an untrusted mapping document accepted for parsing.
///
/// F10 (DoS): `serde_yaml`/`serde_json` have no built-in pre-parse byte cap, so
/// a hostile document could rely on alias expansion or sheer size to exhaust
/// memory/CPU before any other limit fires. Reject anything larger first.
const MAX_MAPPING_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

/// Absolute safety cap on a JSON-Pointer array index used during writes.
///
/// F3 (DoS): `write_at` pads an array with nulls up to the target index, so a
/// large attacker-controlled index forces a huge allocation. Compile-time
/// validation against `limits.max_list_len` is the primary defense; this
/// constant is a runtime defense-in-depth guard for the path where `limits` is
/// not reachable (the compiled mapping does not retain `SecurityLimits`). The
/// value is intentionally generous so legitimate mappings are unaffected.
const MAX_ARRAY_INDEX: usize = 1_000_000;

/// Maximum number of full transformation-log entries retained per evaluation.
///
/// F9 (DoS): in non-Production privacy modes each log entry embeds full
/// `resolved_input`/`resolved_output` JSON; over many rules this is unbounded
/// memory. Once this cap is reached we stop retaining further entries (after a
/// single truncation marker) instead of growing without bound.
const MAX_LOG_ENTRIES: usize = 10_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicSchemaBindingMode {
    #[default]
    PublicSchemaV1,
    LegacyV01,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicSchemaDirection {
    #[default]
    ToTarget,
    FromTarget,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    #[default]
    Production,
    Authoring,
    Debug,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PublicSchemaCompileOptions {
    #[serde(default)]
    pub binding_mode: Option<PublicSchemaBindingMode>,
    #[serde(default)]
    pub helper_registry_version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicSchemaEvaluateOptions {
    #[serde(default)]
    pub direction: PublicSchemaDirection,
    #[serde(default)]
    pub errors_mode: Option<String>,
    #[serde(default)]
    pub privacy: PrivacyMode,
}

impl Default for PublicSchemaEvaluateOptions {
    fn default() -> Self {
        Self {
            direction: PublicSchemaDirection::ToTarget,
            errors_mode: None,
            privacy: PrivacyMode::Production,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicSchemaEvaluationInput {
    pub source: JsonValue,
    #[serde(default)]
    pub context: JsonValue,
    #[serde(default)]
    pub options: PublicSchemaEvaluateOptions,
}

#[derive(Clone, Debug, Serialize)]
pub struct PublicSchemaCompileMeta {
    pub mapping_id: Option<String>,
    pub version: String,
    pub source: Option<String>,
    pub target: Option<String>,
    pub deterministic_hash: String,
    /// One of "canonical" or "advisory-unimplemented" per spec §11.1.
    pub hash_status: String,
    pub binding_mode: PublicSchemaBindingMode,
    pub property_mapping_count: usize,
    pub expression_count: usize,
    pub warnings: Vec<MappingError>,
}

#[derive(Debug)]
pub struct CompiledPublicSchemaMapping {
    pub meta: PublicSchemaCompileMeta,
    rules: Vec<CompiledPublicSchemaRule>,
    code_systems: Arc<CodeSystemRegistry>,
    limits: SecurityLimits,
}

#[derive(Debug)]
struct CompiledPublicSchemaRule {
    authored: PropertyMappingYaml,
    to_target: Option<CompiledCel>,
    from_target: Option<CompiledCel>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicSchemaRuleLogEntry {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub source_path: String,
    pub target_path: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_input: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_output: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<MappingError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicSchemaTransformOutput {
    pub ok: bool,
    pub output: JsonValue,
    pub log: Vec<PublicSchemaRuleLogEntry>,
    pub warnings: Vec<MappingError>,
    pub errors: Vec<MappingError>,
}

#[derive(Clone, Debug, Deserialize)]
struct PublicSchemaMappingDocument {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    mapping_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    source: Option<JsonValue>,
    #[serde(default)]
    target: Option<JsonValue>,
    #[serde(default)]
    runtime: RuntimeYaml,
    #[serde(default)]
    property_mappings: Vec<PropertyMappingYaml>,
    #[serde(default)]
    records: Option<JsonValue>,
    #[serde(flatten)]
    extra: BTreeMap<String, JsonValue>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct RuntimeYaml {
    #[serde(default)]
    bindings: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct PropertyMappingYaml {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    rule_id: Option<String>,
    source: String,
    target: String,
    #[serde(default)]
    formula: Option<FormulaYaml>,
    #[serde(default)]
    value_mappings: Vec<ValueMappingYaml>,
    #[serde(default)]
    required: bool,
    #[serde(flatten)]
    extra: BTreeMap<String, JsonValue>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ValueMappingYaml {
    source_value: String,
    #[serde(default)]
    target_value: Option<String>,
    #[serde(default)]
    quality: Option<String>,
    #[serde(default)]
    ignored: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum FormulaYaml {
    String(String),
    Directions {
        #[serde(default)]
        to_target: Option<FormulaEntryYaml>,
        #[serde(default)]
        from_target: Option<FormulaEntryYaml>,
    },
}

#[derive(Clone, Debug, Deserialize)]
struct FormulaEntryYaml {
    #[serde(default)]
    expression: Option<String>,
}

pub fn compile_publicschema_mapping(
    text: &str,
    limits: &SecurityLimits,
    mut registry: CodeSystemRegistry,
    runtime_default_errors_mode: Option<&str>,
    options: PublicSchemaCompileOptions,
) -> Result<CompiledPublicSchemaMapping, CompileError> {
    let doc = parse_publicschema_document(text)?;
    if doc.property_mappings.is_empty() {
        return Err(CompileError::Mapping(
            "PublicSchema mapping must contain property_mappings".into(),
        ));
    }
    if doc.records.is_some() {
        return Err(CompileError::Mapping(
            "PublicSchema v0.2 documents cannot also contain v0.1 records".into(),
        ));
    }
    let version = doc.version.clone().unwrap_or_else(|| "0.2".into());
    if version == "0.1" {
        return Err(CompileError::Mapping(
            "version 0.1 cannot be used with property_mappings".into(),
        ));
    }
    let mut warnings = Vec::new();
    if doc.version.is_none() {
        warnings.push(
            MappingError::error(
                ErrorCode::ValidationError,
                "missing version; property_mappings imply PublicSchema v0.2",
                Some("version".into()),
                None,
            )
            .warning(),
        );
    }
    let binding_mode = resolve_binding_mode(&doc, options.binding_mode)?;
    merge_code_systems(&mut registry, &extract_code_systems(&doc))
        .map_err(|e| CompileError::Mapping(e.to_string()))?;
    let codes = Arc::new(registry);

    let mut expression_count = 0usize;
    let mut rules = Vec::with_capacity(doc.property_mappings.len());
    for (idx, pm) in doc.property_mappings.iter().enumerate() {
        validate_pointer(&pm.source, format!("property_mappings[{idx}].source"))?;
        validate_target_pointer(
            &pm.target,
            format!("property_mappings[{idx}].target"),
            limits.max_list_len,
        )?;
        validate_formula_entries(&pm.formula, idx)?;
        validate_value_mappings(&pm.value_mappings, idx)?;
        let to_target = formula_expression(&pm.formula, PublicSchemaDirection::ToTarget)
            .filter(|expr| expr.trim() != "source")
            .map(|expr| {
                expression_count += 1;
                compile_expr(
                    expr,
                    limits,
                    format!("property_mappings[{idx}].formula.to_target.expression"),
                )
            })
            .transpose()?;
        let from_target = formula_expression(&pm.formula, PublicSchemaDirection::FromTarget)
            .filter(|expr| expr.trim() != "source")
            .map(|expr| {
                expression_count += 1;
                compile_expr(
                    expr,
                    limits,
                    format!("property_mappings[{idx}].formula.from_target.expression"),
                )
            })
            .transpose()?;
        rules.push(CompiledPublicSchemaRule {
            authored: pm.clone(),
            to_target,
            from_target,
        });
    }

    let hash = deterministic_hash(
        &doc,
        binding_mode,
        options
            .helper_registry_version
            .as_deref()
            .unwrap_or("builtin"),
    );
    let meta = PublicSchemaCompileMeta {
        mapping_id: doc
            .mapping_id
            .clone()
            .or(doc.id.clone())
            .or(doc.name.clone()),
        version,
        source: endpoint_string(doc.source.as_ref()),
        target: endpoint_string(doc.target.as_ref()),
        deterministic_hash: hash,
        hash_status: "canonical".to_string(),
        binding_mode,
        property_mapping_count: doc.property_mappings.len(),
        expression_count,
        warnings,
    };
    // runtime_default_errors_mode does not affect the canonical hash per spec §11.1.
    let _ = runtime_default_errors_mode;
    Ok(CompiledPublicSchemaMapping {
        meta,
        rules,
        code_systems: codes,
        limits: limits.clone(),
    })
}

pub fn evaluate_publicschema_mapping(
    mapping: &CompiledPublicSchemaMapping,
    input: PublicSchemaEvaluationInput,
) -> PublicSchemaTransformOutput {
    let mode = ErrorMode::parse(input.options.errors_mode.as_deref());
    let mut output = JsonValue::Object(Map::new());
    let mut log = Vec::new();
    let mut errors = Vec::new();
    let mut warnings = mapping.meta.warnings.clone();
    let mut written = BTreeSet::new();
    let ctx = normalize_context(input.context);
    let root = input.source;

    for (idx, rule) in mapping.rules.iter().enumerate() {
        let direction = input.options.direction;
        let (read_ptr, write_ptr, cel) = match direction {
            PublicSchemaDirection::ToTarget => (
                rule.authored.source.as_str(),
                rule.authored.target.as_str(),
                rule.to_target.as_ref(),
            ),
            PublicSchemaDirection::FromTarget => (
                rule.authored.target.as_str(),
                rule.authored.source.as_str(),
                rule.from_target.as_ref(),
            ),
        };
        let rule_id = rule
            .authored
            .id
            .as_deref()
            .or(rule.authored.rule_id.as_deref());
        let quality = rule_quality(rule);
        let expression_for_log = || selected_formula_source(rule, direction);
        if !written.insert(write_ptr.to_string()) {
            warnings.push(
                MappingError::error(
                    ErrorCode::ValidationError,
                    format!("multiple rules write target pointer {write_ptr}; last write wins"),
                    Some(format!("property_mappings[{idx}].target")),
                    None,
                )
                .warning(),
            );
        }

        let Some(resolved) = read_pointer(&root, read_ptr) else {
            let (status, issues) = if rule.authored.required {
                let err = MappingError::error(
                    ErrorCode::MissingRequiredValue,
                    format!("required source pointer {read_ptr} is missing"),
                    Some(format!("property_mappings[{idx}].source")),
                    None,
                );
                ("missing", vec![err.clone()])
            } else {
                ("defaulted", Vec::new())
            };
            push_log(
                &mut log,
                LogFields {
                    index: idx,
                    rule_id,
                    source_path: read_ptr,
                    target_path: write_ptr,
                    status,
                    expression: expression_for_log(),
                    resolved_input: None,
                    resolved_output: None,
                    quality,
                    issues: issues.clone(),
                    privacy: input.options.privacy,
                },
            );
            if rule.authored.required {
                let err = issues.into_iter().next().unwrap_or_else(|| {
                    MappingError::error(
                        ErrorCode::MissingRequiredValue,
                        format!("required source pointer {read_ptr} is missing"),
                        Some(format!("property_mappings[{idx}].source")),
                        None,
                    )
                });
                if push_error(&mut errors, &mut warnings, err, mode) {
                    break;
                }
            }
            continue;
        };

        let formula_key_exists = formula_has_direction(&rule.authored.formula, direction);
        let formula_any_exists = rule.authored.formula.is_some();
        let value = if let Some(cel) = cel {
            match eval_rule_expression(cel, resolved, &root, &ctx, mapping, direction) {
                Ok(v) => v,
                Err(e) => {
                    let err = MappingError::error(
                        ErrorCode::EvaluationError,
                        e,
                        Some(format!("property_mappings[{idx}].formula")),
                        Some(cel.source.clone()),
                    );
                    push_log(
                        &mut log,
                        LogFields {
                            index: idx,
                            rule_id,
                            source_path: read_ptr,
                            target_path: write_ptr,
                            status: "formula_error",
                            expression: Some(cel.source.clone()),
                            resolved_input: Some(resolved.clone()),
                            resolved_output: None,
                            quality,
                            issues: vec![err.clone()],
                            privacy: input.options.privacy,
                        },
                    );
                    if push_error(&mut errors, &mut warnings, err, mode) {
                        break;
                    }
                    continue;
                }
            }
        } else if formula_any_exists && !formula_key_exists {
            let err = MappingError::error(
                ErrorCode::ValidationError,
                format!(
                    "formula is not defined for direction {direction:?}; identity fallback is forbidden",
                ),
                Some(format!("property_mappings[{idx}].formula")),
                None,
            );
            push_log(
                &mut log,
                LogFields {
                    index: idx,
                    rule_id,
                    source_path: read_ptr,
                    target_path: write_ptr,
                    status: "formula_error",
                    expression: None,
                    resolved_input: Some(resolved.clone()),
                    resolved_output: None,
                    quality,
                    issues: vec![err.clone()],
                    privacy: input.options.privacy,
                },
            );
            if push_error(&mut errors, &mut warnings, err, mode) {
                break;
            }
            continue;
        } else {
            resolved.clone()
        };

        let value = match apply_value_mappings(&rule.authored.value_mappings, direction, &value) {
            ValueMappingOutcome::Mapped(mapped) => mapped,
            ValueMappingOutcome::Ignored => {
                push_log(
                    &mut log,
                    LogFields {
                        index: idx,
                        rule_id,
                        source_path: read_ptr,
                        target_path: write_ptr,
                        status: "skipped",
                        expression: expression_for_log(),
                        resolved_input: Some(resolved.clone()),
                        resolved_output: None,
                        quality,
                        issues: Vec::new(),
                        privacy: input.options.privacy,
                    },
                );
                continue;
            }
            ValueMappingOutcome::Unmapped => {
                let value_role = match direction {
                    PublicSchemaDirection::ToTarget => "source",
                    PublicSchemaDirection::FromTarget => "target",
                };
                let err = MappingError::error(
                    ErrorCode::ValidationError,
                    format!(
                        "no value_mapping row for {value_role} value {}",
                        value_for_message(&value)
                    ),
                    Some(format!("property_mappings[{idx}].value_mappings")),
                    expression_for_log(),
                );
                push_log(
                    &mut log,
                    LogFields {
                        index: idx,
                        rule_id,
                        source_path: read_ptr,
                        target_path: write_ptr,
                        status: "value_unmapped",
                        expression: expression_for_log(),
                        resolved_input: Some(resolved.clone()),
                        resolved_output: None,
                        quality,
                        issues: vec![err.clone()],
                        privacy: input.options.privacy,
                    },
                );
                if push_error(&mut errors, &mut warnings, err, mode) {
                    break;
                }
                continue;
            }
            ValueMappingOutcome::AmbiguousReverse {
                target_value,
                source_values,
            } => {
                let err = MappingError::error(
                    ErrorCode::ValidationError,
                    format!(
                        "ambiguous reverse value_mapping for target value {target_value:?}; matching source values: {}",
                        source_values.join(", ")
                    ),
                    Some(format!("property_mappings[{idx}].value_mappings")),
                    expression_for_log(),
                );
                push_log(
                    &mut log,
                    LogFields {
                        index: idx,
                        rule_id,
                        source_path: read_ptr,
                        target_path: write_ptr,
                        status: "value_unmapped",
                        expression: expression_for_log(),
                        resolved_input: Some(resolved.clone()),
                        resolved_output: None,
                        quality,
                        issues: vec![err.clone()],
                        privacy: input.options.privacy,
                    },
                );
                if push_error(&mut errors, &mut warnings, err, mode) {
                    break;
                }
                continue;
            }
        };

        if let Err(message) = write_pointer(&mut output, write_ptr, value.clone(), MAX_ARRAY_INDEX)
        {
            let err = MappingError::error(
                ErrorCode::TypeError,
                message,
                Some(format!("property_mappings[{idx}].target")),
                expression_for_log(),
            );
            push_log(
                &mut log,
                LogFields {
                    index: idx,
                    rule_id,
                    source_path: read_ptr,
                    target_path: write_ptr,
                    status: "write_error",
                    expression: expression_for_log(),
                    resolved_input: Some(resolved.clone()),
                    resolved_output: Some(value.clone()),
                    quality,
                    issues: vec![err.clone()],
                    privacy: input.options.privacy,
                },
            );
            if push_error(&mut errors, &mut warnings, err, mode) {
                break;
            }
            continue;
        }
        push_log(
            &mut log,
            LogFields {
                index: idx,
                rule_id,
                source_path: read_ptr,
                target_path: write_ptr,
                status: "applied",
                expression: expression_for_log(),
                resolved_input: Some(resolved.clone()),
                resolved_output: Some(value),
                quality,
                issues: Vec::new(),
                privacy: input.options.privacy,
            },
        );
    }

    PublicSchemaTransformOutput {
        ok: errors.is_empty(),
        output,
        log,
        warnings,
        errors,
    }
}

pub fn preview_publicschema_rule_expression(
    mapping_rule: &JsonValue,
    sample_record: JsonValue,
    direction: PublicSchemaDirection,
    ctx: JsonValue,
    limits: &SecurityLimits,
    codes: Arc<CodeSystemRegistry>,
) -> ExpressionPreviewResult {
    let rule: PropertyMappingYaml = match serde_json::from_value(mapping_rule.clone()) {
        Ok(r) => r,
        Err(e) => {
            return ExpressionPreviewResult::from_parts(
                "".into(),
                None,
                vec![crosswalk_cel::ExpressionIssue {
                    phase: crosswalk_cel::ExpressionPhase::Evaluation,
                    severity: ErrorSeverity::Error,
                    code: ErrorCode::ValidationError,
                    message: e.to_string(),
                    line: None,
                    column: None,
                    expression: "".into(),
                    source_path: None,
                }],
            );
        }
    };
    let expr = formula_expression(&rule.formula, direction).unwrap_or("source");
    crosswalk_cel::preview_cel_expression(expr, sample_record, ctx, limits, codes)
}

fn parse_publicschema_document(text: &str) -> Result<PublicSchemaMappingDocument, CompileError> {
    // F10 (DoS): cap the untrusted document size before parsing. `serde_yaml`
    // has no pre-parse byte cap, so a hostile document could exploit alias
    // expansion or sheer size to exhaust memory/CPU before any later limit fires.
    if text.len() > MAX_MAPPING_DOCUMENT_BYTES {
        return Err(CompileError::Mapping(format!(
            "mapping document is {} bytes, exceeds maximum of {MAX_MAPPING_DOCUMENT_BYTES} bytes",
            text.len()
        )));
    }
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        serde_json::from_str(text).map_err(|e| CompileError::Mapping(e.to_string()))
    } else {
        serde_yaml::from_str(text)
            .map_err(|err| CompileError::Mapping(format!("YAML parse error: {err}")))
    }
}

fn resolve_binding_mode(
    doc: &PublicSchemaMappingDocument,
    option: Option<PublicSchemaBindingMode>,
) -> Result<PublicSchemaBindingMode, CompileError> {
    if let Some(mode) = option {
        return Ok(mode);
    }
    match doc.runtime.bindings.as_deref() {
        None | Some("") | Some("publicschema-v1") | Some("publicschema_v1") => {
            Ok(PublicSchemaBindingMode::PublicSchemaV1)
        }
        Some("legacy-v0.1") | Some("legacy_v0_1") => Ok(PublicSchemaBindingMode::LegacyV01),
        Some(other) => Err(CompileError::Mapping(format!(
            "unknown PublicSchema binding mode {other}"
        ))),
    }
}

fn extract_code_systems(doc: &PublicSchemaMappingDocument) -> BTreeMap<String, serde_yaml::Value> {
    doc.extra
        .get("code_systems")
        .and_then(|v| serde_yaml::to_value(v).ok())
        .and_then(|v| match v {
            serde_yaml::Value::Mapping(m) => Some(
                m.into_iter()
                    .filter_map(|(k, v)| k.as_str().map(|s| (s.to_string(), v)))
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

fn merge_code_systems(
    registry: &mut CodeSystemRegistry,
    systems: &BTreeMap<String, serde_yaml::Value>,
) -> Result<(), FunctionError> {
    for (name, raw) in systems {
        registry.merge_document(name, code_system_document_from_yaml(raw)?)?;
    }
    Ok(())
}

fn code_system_document_from_yaml(
    raw: &serde_yaml::Value,
) -> Result<CodeSystemDocument, FunctionError> {
    let obj = raw
        .as_mapping()
        .ok_or_else(|| FunctionError::new("CODE_SYSTEM_INVALID", "code_system must be mapping"))?;
    let mut entries = BTreeMap::new();
    for (key, value) in obj {
        let source_key = key
            .as_str()
            .ok_or_else(|| FunctionError::new("CODE_SYSTEM_INVALID", "non-string key"))?
            .to_string();
        entries.insert(
            source_key.clone(),
            code_entry_from_yaml(value, &source_key)?,
        );
    }
    Ok(CodeSystemDocument { entries })
}

fn code_entry_from_yaml(
    value: &serde_yaml::Value,
    source_key: &str,
) -> Result<CodeEntry, FunctionError> {
    if let Some(id) = value.as_str() {
        return Ok(CodeEntry {
            id: id.to_string(),
            label: BTreeMap::new(),
            aliases: Vec::new(),
            extra: Default::default(),
        });
    }
    let mapping = value
        .as_mapping()
        .ok_or_else(|| FunctionError::new("CODE_SYSTEM_INVALID", "entry must be string or map"))?;
    let id = mapping
        .get(serde_yaml::Value::String("id".into()))
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| {
            FunctionError::new(
                "CODE_SYSTEM_INVALID",
                format!("missing id for {source_key}"),
            )
        })?;
    let mut label = BTreeMap::new();
    if let Some(labels) = mapping.get(serde_yaml::Value::String("label".into())) {
        if let Some(labels) = labels.as_mapping() {
            for (key, value) in labels {
                if let (Some(key), Some(value)) = (key.as_str(), value.as_str()) {
                    label.insert(key.to_string(), value.to_string());
                }
            }
        }
    }
    let aliases = mapping
        .get(serde_yaml::Value::String("aliases".into()))
        .and_then(|value| value.as_sequence())
        .map(|items| {
            items
                .iter()
                .filter_map(|value| value.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default();
    let mut extra = std::collections::HashMap::new();
    for (key, value) in mapping {
        let Some(key) = key.as_str() else {
            continue;
        };
        if matches!(key, "id" | "label" | "aliases") {
            continue;
        }
        let value = serde_json::to_value(value).unwrap_or(JsonValue::Null);
        extra.insert(key.to_string(), value);
    }
    Ok(CodeEntry {
        id,
        label,
        aliases,
        extra,
    })
}

fn validate_pointer(pointer: &str, path: String) -> Result<(), CompileError> {
    if pointer.is_empty() {
        return Ok(());
    }
    if !pointer.starts_with('/') {
        return Err(CompileError::Mapping(format!(
            "{path} must be an RFC 6901 JSON Pointer"
        )));
    }
    Ok(())
}

fn validate_target_pointer(
    pointer: &str,
    path: String,
    max_index: usize,
) -> Result<(), CompileError> {
    validate_pointer(pointer, path.clone())?;
    // F3 (DoS): reject numeric array-index segments above `max_index` so a
    // target like `/x/100000000` cannot force a huge null-padding allocation
    // in `write_at` at evaluation time. Source pointers are not capped here:
    // numeric source segments can be ordinary object keys and never allocate.
    if let Some(segments) = pointer_segments(pointer) {
        for seg in &segments {
            if let Ok(idx) = seg.parse::<usize>() {
                if idx > max_index {
                    return Err(CompileError::Mapping(format!(
                        "{path} array index {idx} exceeds maximum of {max_index}"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn formula_expression(
    formula: &Option<FormulaYaml>,
    direction: PublicSchemaDirection,
) -> Option<&str> {
    match formula.as_ref()? {
        FormulaYaml::String(s) => {
            if direction == PublicSchemaDirection::ToTarget {
                Some(s.as_str())
            } else {
                None
            }
        }
        FormulaYaml::Directions {
            to_target,
            from_target,
        } => match direction {
            PublicSchemaDirection::ToTarget => to_target
                .as_ref()
                .and_then(|f| f.expression.as_deref())
                .filter(|s| !s.trim().is_empty()),
            PublicSchemaDirection::FromTarget => from_target
                .as_ref()
                .and_then(|f| f.expression.as_deref())
                .filter(|s| !s.trim().is_empty()),
        },
    }
}

fn validate_formula_entries(formula: &Option<FormulaYaml>, idx: usize) -> Result<(), CompileError> {
    let Some(FormulaYaml::Directions {
        to_target,
        from_target,
    }) = formula
    else {
        return Ok(());
    };
    for (name, entry) in [("to_target", to_target), ("from_target", from_target)] {
        if entry
            .as_ref()
            .is_some_and(|f| f.expression.as_deref().unwrap_or("").trim().is_empty())
        {
            return Err(CompileError::Mapping(format!(
                "property_mappings[{idx}].formula.{name}.expression cannot be empty"
            )));
        }
    }
    Ok(())
}

fn validate_value_mappings(
    value_mappings: &[ValueMappingYaml],
    idx: usize,
) -> Result<(), CompileError> {
    for (row_idx, row) in value_mappings.iter().enumerate() {
        if row.source_value.trim().is_empty() {
            return Err(CompileError::Mapping(format!(
                "property_mappings[{idx}].value_mappings[{row_idx}].source_value cannot be empty"
            )));
        }
        if row.ignored && row.target_value.as_deref().is_some_and(|v| !v.is_empty()) {
            return Err(CompileError::Mapping(format!(
                "property_mappings[{idx}].value_mappings[{row_idx}] cannot be ignored and have target_value"
            )));
        }
    }
    Ok(())
}

fn formula_has_direction(formula: &Option<FormulaYaml>, direction: PublicSchemaDirection) -> bool {
    match formula {
        None => false,
        Some(FormulaYaml::String(s)) => {
            direction == PublicSchemaDirection::ToTarget && !s.is_empty()
        }
        Some(FormulaYaml::Directions {
            to_target,
            from_target,
        }) => match direction {
            PublicSchemaDirection::ToTarget => to_target.is_some(),
            PublicSchemaDirection::FromTarget => from_target.is_some(),
        },
    }
}

fn selected_formula_source(
    rule: &CompiledPublicSchemaRule,
    direction: PublicSchemaDirection,
) -> Option<String> {
    match direction {
        PublicSchemaDirection::ToTarget => rule.to_target.as_ref().map(|c| c.source.clone()),
        PublicSchemaDirection::FromTarget => rule.from_target.as_ref().map(|c| c.source.clone()),
    }
    .or_else(|| {
        formula_expression(&rule.authored.formula, direction)
            .filter(|s| *s == "source")
            .map(ToString::to_string)
    })
}

fn eval_rule_expression(
    cel: &CompiledCel,
    source: &JsonValue,
    root: &JsonValue,
    ctx: &JsonValue,
    mapping: &CompiledPublicSchemaMapping,
    direction: PublicSchemaDirection,
) -> Result<JsonValue, String> {
    // Per spec §6.1: bind ONLY the direction-appropriate alias to the input record.
    // ToTarget (forward): `target` aliases root; `profile` is absent.
    // FromTarget (reverse): `profile` aliases root; `target` is absent.
    let mut root_bindings = BTreeMap::from([
        ("source".to_string(), source.clone()),
        ("root".to_string(), root.clone()),
        ("ctx".to_string(), ctx.clone()),
        ("vars".to_string(), JsonValue::Object(Map::new())),
        ("index".to_string(), JsonValue::Null),
    ]);
    match direction {
        PublicSchemaDirection::ToTarget => {
            root_bindings.insert("target".to_string(), root.clone());
        }
        PublicSchemaDirection::FromTarget => {
            root_bindings.insert("profile".to_string(), root.clone());
        }
    }

    evaluate_compiled_expression_with_input_and_limits(
        cel,
        StandaloneExpressionInput::new(root_bindings),
        &mapping.limits,
        Arc::clone(&mapping.code_systems),
    )
    .map_err(|err| err.to_string())
}

enum ValueMappingOutcome {
    Mapped(JsonValue),
    Ignored,
    Unmapped,
    AmbiguousReverse {
        target_value: String,
        source_values: Vec<String>,
    },
}

fn apply_value_mappings(
    value_mappings: &[ValueMappingYaml],
    direction: PublicSchemaDirection,
    value: &JsonValue,
) -> ValueMappingOutcome {
    if value_mappings.is_empty() {
        return ValueMappingOutcome::Mapped(value.clone());
    }
    let Some(value_key) = scalar_key(value) else {
        return ValueMappingOutcome::Unmapped;
    };
    if direction == PublicSchemaDirection::FromTarget {
        let mut matches = value_mappings
            .iter()
            .filter(|row| row.target_value.as_deref() == Some(value_key.as_str()));
        let Some(first) = matches.next() else {
            return ValueMappingOutcome::Unmapped;
        };
        let mut source_values = BTreeSet::from([first.source_value.clone()]);
        for row in matches {
            source_values.insert(row.source_value.clone());
        }
        if source_values.len() > 1 {
            return ValueMappingOutcome::AmbiguousReverse {
                target_value: value_key,
                source_values: source_values.into_iter().collect(),
            };
        }
        return ValueMappingOutcome::Mapped(JsonValue::String(first.source_value.clone()));
    }

    let matched = value_mappings
        .iter()
        .find(|row| row.source_value == value_key);
    let Some(row) = matched else {
        return ValueMappingOutcome::Unmapped;
    };
    if row.ignored {
        return ValueMappingOutcome::Ignored;
    }
    match direction {
        PublicSchemaDirection::ToTarget => row
            .target_value
            .as_ref()
            .map(|target| ValueMappingOutcome::Mapped(JsonValue::String(target.clone())))
            .unwrap_or(ValueMappingOutcome::Ignored),
        PublicSchemaDirection::FromTarget => unreachable!("handled above"),
    }
}

fn scalar_key(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::String(s) => Some(s.clone()),
        JsonValue::Number(n) => Some(n.to_string()),
        JsonValue::Bool(b) => Some(b.to_string()),
        JsonValue::Null | JsonValue::Array(_) | JsonValue::Object(_) => None,
    }
}

fn value_for_message(value: &JsonValue) -> String {
    match value {
        JsonValue::String(s) => format!("{s:?}"),
        other => other.to_string(),
    }
}

fn normalize_context(ctx: JsonValue) -> JsonValue {
    match ctx {
        JsonValue::Null => JsonValue::Object(Map::new()),
        JsonValue::Object(_) => ctx,
        other => JsonValue::Object(Map::from_iter([("value".into(), other)])),
    }
}

fn push_error(
    errors: &mut Vec<MappingError>,
    warnings: &mut Vec<MappingError>,
    err: MappingError,
    mode: ErrorMode,
) -> bool {
    match mode {
        ErrorMode::Strict => {
            errors.push(err);
            true
        }
        ErrorMode::Collect => {
            errors.push(err);
            false
        }
        ErrorMode::Lenient => {
            warnings.push(err.warning());
            false
        }
    }
}

struct LogFields<'a> {
    index: usize,
    rule_id: Option<&'a str>,
    source_path: &'a str,
    target_path: &'a str,
    status: &'a str,
    expression: Option<String>,
    resolved_input: Option<JsonValue>,
    resolved_output: Option<JsonValue>,
    quality: Option<&'a str>,
    issues: Vec<MappingError>,
    privacy: PrivacyMode,
}

fn push_log(log: &mut Vec<PublicSchemaRuleLogEntry>, fields: LogFields<'_>) {
    // F9 (DoS): in non-Production privacy modes each entry embeds full
    // resolved input/output JSON, so the log is otherwise unbounded over many
    // rules. Once the cap is reached, push a single truncation marker and stop
    // retaining further entries.
    if log.len() >= MAX_LOG_ENTRIES {
        if log.len() == MAX_LOG_ENTRIES {
            log.push(PublicSchemaRuleLogEntry {
                index: fields.index,
                rule_id: None,
                source_path: fields.source_path.to_string(),
                target_path: fields.target_path.to_string(),
                status: "log_truncated".to_string(),
                expression: None,
                resolved_input: None,
                resolved_output: None,
                quality: None,
                issues: Vec::new(),
            });
        }
        return;
    }
    let include_values = !matches!(fields.privacy, PrivacyMode::Production);
    log.push(PublicSchemaRuleLogEntry {
        index: fields.index,
        rule_id: fields.rule_id.map(ToString::to_string),
        source_path: fields.source_path.to_string(),
        target_path: fields.target_path.to_string(),
        status: fields.status.to_string(),
        expression: fields.expression,
        resolved_input: include_values.then_some(fields.resolved_input).flatten(),
        resolved_output: include_values.then_some(fields.resolved_output).flatten(),
        quality: fields.quality.map(ToString::to_string),
        issues: fields.issues,
    });
}

fn rule_quality(rule: &CompiledPublicSchemaRule) -> Option<&str> {
    rule.authored.extra.get("quality").and_then(|v| v.as_str())
}

fn read_pointer<'a>(value: &'a JsonValue, pointer: &str) -> Option<&'a JsonValue> {
    if pointer.is_empty() {
        return Some(value);
    }
    let mut cur = value;
    for seg in pointer_segments(pointer)? {
        match cur {
            JsonValue::Object(m) => cur = m.get(&seg)?,
            JsonValue::Array(a) => {
                let idx = seg.parse::<usize>().ok()?;
                cur = a.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

fn write_pointer(
    root: &mut JsonValue,
    pointer: &str,
    value: JsonValue,
    max_index: usize,
) -> Result<(), String> {
    if pointer.is_empty() {
        *root = value;
        return Ok(());
    }
    let segments = pointer_segments(pointer).ok_or_else(|| "invalid JSON Pointer".to_string())?;
    write_at(root, &segments, value, max_index)
}

fn write_at(
    cur: &mut JsonValue,
    segments: &[String],
    value: JsonValue,
    max_index: usize,
) -> Result<(), String> {
    if segments.is_empty() {
        *cur = value;
        return Ok(());
    }
    let head = &segments[0];
    let rest = &segments[1..];
    if cur.is_null() {
        *cur = if is_array_segment(head) {
            JsonValue::Array(Vec::new())
        } else {
            JsonValue::Object(Map::new())
        };
    }
    match cur {
        JsonValue::Object(m) => {
            if rest.is_empty() {
                m.insert(head.clone(), value);
                Ok(())
            } else {
                let child = m.entry(head.clone()).or_insert_with(|| {
                    if is_array_segment(&rest[0]) {
                        JsonValue::Array(Vec::new())
                    } else {
                        JsonValue::Object(Map::new())
                    }
                });
                write_at(child, rest, value, max_index)
            }
        }
        JsonValue::Array(a) => {
            if head == "-" {
                if rest.is_empty() {
                    a.push(value);
                    return Ok(());
                }
                a.push(if is_array_segment(&rest[0]) {
                    JsonValue::Array(Vec::new())
                } else {
                    JsonValue::Object(Map::new())
                });
                let last = a.len() - 1;
                return write_at(&mut a[last], rest, value, max_index);
            }
            let idx = head
                .parse::<usize>()
                .map_err(|_| format!("array segment {head:?} is not numeric"))?;
            // F3 (DoS): defense-in-depth. The pad loop below grows the array up
            // to `idx`, so a large attacker-controlled index would force a huge
            // allocation. Reject indices above the safety cap before padding or
            // writing.
            if idx > max_index {
                return Err(format!("array index {idx} exceeds max {max_index}"));
            }
            while a.len() <= idx {
                a.push(JsonValue::Null);
            }
            if rest.is_empty() {
                a[idx] = value;
                Ok(())
            } else {
                if a[idx].is_null() {
                    a[idx] = if is_array_segment(&rest[0]) {
                        JsonValue::Array(Vec::new())
                    } else {
                        JsonValue::Object(Map::new())
                    };
                }
                write_at(&mut a[idx], rest, value, max_index)
            }
        }
        _ => Err(format!(
            "cannot write through non-container at JSON Pointer segment {head}"
        )),
    }
}

fn pointer_segments(pointer: &str) -> Option<Vec<String>> {
    if !pointer.starts_with('/') {
        return None;
    }
    let mut out = Vec::new();
    for raw in pointer[1..].split('/') {
        let mut decoded = String::with_capacity(raw.len());
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c == '~' {
                match chars.next() {
                    // RFC 6901 §3: ~1 → /, ~0 → ~. Other escapes are invalid.
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => return None,
                }
            } else {
                decoded.push(c);
            }
        }
        out.push(decoded);
    }
    Some(out)
}

fn is_array_segment(seg: &str) -> bool {
    seg == "-" || seg.parse::<usize>().is_ok()
}

fn endpoint_string(value: Option<&JsonValue>) -> Option<String> {
    match value? {
        JsonValue::String(s) => Some(s.clone()),
        JsonValue::Object(m) => m
            .get("id")
            .or_else(|| m.get("url"))
            .or_else(|| m.get("name"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        _ => None,
    }
}

fn deterministic_hash(
    doc: &PublicSchemaMappingDocument,
    binding_mode: PublicSchemaBindingMode,
    helper_registry_version: &str,
) -> String {
    // Per spec §11.1: property_mappings preserve document order; all other object keys
    // are emitted in sorted order by the canonical serializer below.
    let rules: Vec<JsonValue> = doc
        .property_mappings
        .iter()
        .map(|pm| {
            json!({
                "id": pm.id,
                "rule_id": pm.rule_id,
                "source": pm.source,
                "target": pm.target,
                "formula": formula_json(&pm.formula),
                "value_mappings": pm.value_mappings,
                "required": pm.required,
                "extra": pm.extra,
            })
        })
        .collect();
    let canonical = json!({
        "schema": "crosswalk-publicschema-v0.2",
        "mapping_id": doc.mapping_id.as_ref().or(doc.id.as_ref()).or(doc.name.as_ref()),
        "version": doc.version.as_deref().unwrap_or("0.2"),
        "source": endpoint_string(doc.source.as_ref()),
        "target": endpoint_string(doc.target.as_ref()),
        "runtime_bindings": binding_mode,
        "helper_registry_version": helper_registry_version,
        "property_mappings": rules,
    });
    let mut bytes = Vec::new();
    write_canonical_json(&canonical, &mut bytes);
    hex::encode(Sha256::digest(&bytes))
}

/// Canonical JSON writer per spec §11.1: sorted object keys, preserved array order,
/// no insignificant whitespace, UTF-8. Independent of serde_json's Map iteration
/// order so the hash remains stable across `preserve_order` feature toggles.
fn write_canonical_json(v: &JsonValue, out: &mut Vec<u8>) {
    match v {
        JsonValue::Null => out.extend_from_slice(b"null"),
        JsonValue::Bool(true) => out.extend_from_slice(b"true"),
        JsonValue::Bool(false) => out.extend_from_slice(b"false"),
        JsonValue::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        JsonValue::String(s) => {
            // Reuse serde_json's string escaping (RFC 8259 conformant).
            out.extend_from_slice(serde_json::to_string(s).unwrap_or_default().as_bytes());
        }
        JsonValue::Array(a) => {
            out.push(b'[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical_json(item, out);
            }
            out.push(b']');
        }
        JsonValue::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(serde_json::to_string(*k).unwrap_or_default().as_bytes());
                out.push(b':');
                if let Some(val) = m.get(*k) {
                    write_canonical_json(val, out);
                } else {
                    out.extend_from_slice(b"null");
                }
            }
            out.push(b'}');
        }
    }
}

fn formula_json(formula: &Option<FormulaYaml>) -> JsonValue {
    match formula {
        None => JsonValue::Null,
        Some(FormulaYaml::String(s)) => JsonValue::String(s.clone()),
        Some(FormulaYaml::Directions {
            to_target,
            from_target,
        }) => json!({
            "to_target": to_target.as_ref().and_then(|f| f.expression.clone()),
            "from_target": from_target.as_ref().and_then(|f| f.expression.clone()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_write_creates_arrays_with_padding() {
        let mut out = JsonValue::Null;
        write_pointer(&mut out, "/items/3/name", json!("x"), MAX_ARRAY_INDEX).unwrap();
        assert_eq!(out["items"][0], JsonValue::Null);
        assert_eq!(out["items"][3]["name"], json!("x"));
    }

    #[test]
    fn pointer_write_rejects_over_cap_array_index() {
        // F3 runtime guard: a write to an index above the cap must error
        // rather than padding the array with that many nulls.
        let mut out = JsonValue::Null;
        let err = write_pointer(&mut out, "/x/5", json!("v"), 4).unwrap_err();
        assert!(err.contains("exceeds max"), "unexpected error: {err}");
        // Nested over-cap index is also rejected.
        let mut out2 = JsonValue::Null;
        let err2 = write_pointer(&mut out2, "/a/0/b/9", json!("v"), 4).unwrap_err();
        assert!(err2.contains("exceeds max"), "unexpected error: {err2}");
    }

    #[test]
    fn compile_rejects_target_array_index_above_max_list_len() {
        // F3 compile-time fix: an array index far above max_list_len must be
        // rejected at compile time, before any allocation at evaluation.
        let limits = SecurityLimits {
            max_list_len: 100,
            ..Default::default()
        };
        let doc = r#"
version: "0.2"
property_mappings:
  - source: /a
    target: /x/100000000
"#;
        let err = compile_publicschema_mapping(
            doc,
            &limits,
            CodeSystemRegistry::default(),
            None,
            PublicSchemaCompileOptions::default(),
        )
        .unwrap_err();
        let msg = match err {
            CompileError::Mapping(m) => m,
            other => panic!("expected Mapping error, got {other:?}"),
        };
        assert!(msg.contains("exceeds maximum"), "unexpected error: {msg}");
    }

    #[test]
    fn compile_allows_in_range_array_index() {
        // An index within max_list_len must still compile.
        let limits = SecurityLimits::default();
        let doc = r#"
version: "0.2"
property_mappings:
  - source: /a
    target: /x/3
"#;
        compile_publicschema_mapping(
            doc,
            &limits,
            CodeSystemRegistry::default(),
            None,
            PublicSchemaCompileOptions::default(),
        )
        .expect("in-range index should compile");
    }

    #[test]
    fn compile_allows_large_numeric_source_object_key() {
        let limits = SecurityLimits {
            max_list_len: 100,
            ..Default::default()
        };
        let doc = r#"
version: "0.2"
property_mappings:
  - source: /answers/100000001
    target: /out
"#;
        let compiled = compile_publicschema_mapping(
            doc,
            &limits,
            CodeSystemRegistry::default(),
            None,
            PublicSchemaCompileOptions::default(),
        )
        .expect("large numeric source object key should compile");

        let out = evaluate_publicschema_mapping(
            &compiled,
            PublicSchemaEvaluationInput {
                source: json!({ "answers": { "100000001": "ok" } }),
                context: json!({}),
                options: PublicSchemaEvaluateOptions::default(),
            },
        );

        assert!(out.errors.is_empty(), "{:?}", out.errors);
        assert_eq!(out.output["out"], json!("ok"));
    }

    #[test]
    fn formula_evaluation_uses_compile_time_input_limit() {
        let limits = SecurityLimits {
            max_output_json_bytes: 64,
            ..Default::default()
        };
        let doc = r#"
version: "0.2"
property_mappings:
  - source: /blob
    target: /out
    formula:
      to_target:
        expression: source + ""
"#;
        let compiled = compile_publicschema_mapping(
            doc,
            &limits,
            CodeSystemRegistry::default(),
            None,
            PublicSchemaCompileOptions::default(),
        )
        .expect("mapping should compile");

        let out = evaluate_publicschema_mapping(
            &compiled,
            PublicSchemaEvaluationInput {
                source: json!({ "blob": "x".repeat(4096) }),
                context: json!({}),
                options: PublicSchemaEvaluateOptions::default(),
            },
        );

        assert!(
            out.errors
                .iter()
                .any(|err| err.message.contains("input exceeds max")),
            "expected input limit error, got {:?}",
            out.errors
        );
    }

    #[test]
    fn compile_rejects_oversized_document() {
        // F10: a document larger than MAX_MAPPING_DOCUMENT_BYTES is rejected
        // with a compile error before parsing.
        let limits = SecurityLimits::default();
        let mut doc = String::from("version: \"0.2\"\nproperty_mappings: []\n");
        doc.push_str(&"#".repeat(MAX_MAPPING_DOCUMENT_BYTES + 1));
        let err = compile_publicschema_mapping(
            &doc,
            &limits,
            CodeSystemRegistry::default(),
            None,
            PublicSchemaCompileOptions::default(),
        )
        .unwrap_err();
        let msg = match err {
            CompileError::Mapping(m) => m,
            other => panic!("expected Mapping error, got {other:?}"),
        };
        assert!(msg.contains("exceeds maximum"), "unexpected error: {msg}");
    }

    #[test]
    fn log_is_capped_at_max_entries() {
        // F9: push_log must stop retaining full entries once the cap is hit,
        // appending exactly one truncation marker.
        let mut log: Vec<PublicSchemaRuleLogEntry> = Vec::new();
        for i in 0..(MAX_LOG_ENTRIES + 50) {
            push_log(
                &mut log,
                LogFields {
                    index: i,
                    rule_id: None,
                    source_path: "/a",
                    target_path: "/b",
                    status: "ok",
                    expression: None,
                    resolved_input: None,
                    resolved_output: None,
                    quality: None,
                    issues: Vec::new(),
                    privacy: PrivacyMode::Debug,
                },
            );
        }
        assert_eq!(log.len(), MAX_LOG_ENTRIES + 1);
        assert_eq!(log.last().unwrap().status, "log_truncated");
    }

    #[test]
    fn code_entry_from_yaml_preserves_unjsonable_extra_as_null() {
        let mut bad_extra = serde_yaml::Mapping::new();
        bad_extra.insert(
            serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("nested".into())]),
            serde_yaml::Value::String("x".into()),
        );

        let mut entry = serde_yaml::Mapping::new();
        entry.insert(
            serde_yaml::Value::String("id".into()),
            serde_yaml::Value::String("canonical.example".into()),
        );
        entry.insert(
            serde_yaml::Value::String("metadata".into()),
            serde_yaml::Value::Mapping(bad_extra),
        );

        let parsed = code_entry_from_yaml(&serde_yaml::Value::Mapping(entry), "example").unwrap();

        assert_eq!(parsed.extra.get("metadata"), Some(&JsonValue::Null));
    }
}
