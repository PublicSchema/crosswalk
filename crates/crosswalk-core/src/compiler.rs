use crate::code_system::CodeSystemRegistry;
use crate::compiled::{
    CompiledCel, CompiledField, CompiledMapping, CompiledRecord, CompiledValidation, ErrorMode,
};
use crate::errors::CompileError;
use crate::mapping::MappingDocument;
use crate::security::SecurityLimits;
use std::sync::Arc;

/// Maximum size (in bytes) of an untrusted mapping document accepted for parsing.
///
/// F10 (DoS): `serde_yaml` has no built-in pre-parse byte cap, so a hostile
/// document could rely on alias expansion or sheer size to exhaust memory/CPU
/// before any other limit fires. Reject anything larger before handing it to
/// the YAML parser.
const MAX_MAPPING_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

/// `runtime_default_errors_mode` applies only when the mapping YAML does not set `errors.mode`.
pub fn compile_mapping_yaml(
    yaml: &str,
    limits: &SecurityLimits,
    mut registry: CodeSystemRegistry,
    runtime_default_errors_mode: Option<&str>,
) -> Result<CompiledMapping, CompileError> {
    if yaml.len() > MAX_MAPPING_DOCUMENT_BYTES {
        return Err(CompileError::Mapping(format!(
            "mapping document is {} bytes, exceeds maximum of {MAX_MAPPING_DOCUMENT_BYTES} bytes",
            yaml.len()
        )));
    }
    let doc: MappingDocument = serde_yaml::from_str(yaml)
        .map_err(|err| CompileError::Mapping(format!("YAML parse error: {err}")))?;
    crate::code_system::merge_from_map(&mut registry, &doc.code_systems)
        .map_err(|e| CompileError::Mapping(e.to_string()))?;
    let reg = Arc::new(registry);

    let mut all_expressions = Vec::new();
    let error_mode = if doc.errors.mode.is_some() {
        ErrorMode::parse(doc.errors.mode.as_deref())
    } else {
        ErrorMode::parse(runtime_default_errors_mode)
    };

    let mut records = Vec::new();
    for (name, rec) in &doc.records {
        all_expressions.extend(CompiledMapping::collect_expressions_from_record(rec));
        let emit = rec
            .emit
            .as_ref()
            .map(|e| compile_expr(e, limits, format!("records.{name}.emit")))
            .transpose()?;
        let foreach = rec
            .foreach
            .as_ref()
            .map(|e| compile_expr(e, limits, format!("records.{name}.foreach")))
            .transpose()?;
        let when = rec
            .when
            .as_ref()
            .map(|e| compile_expr(e, limits, format!("records.{name}.when")))
            .transpose()?;
        let mut vars = Vec::new();
        for (vn, ve) in &rec.vars {
            vars.push((
                vn.clone(),
                compile_expr(ve, limits, format!("records.{name}.vars.{vn}"))?,
            ));
        }
        let mut fields = Vec::new();
        for (fnm, fy) in &rec.fields {
            fields.push(CompiledField {
                name: fnm.clone(),
                cel: compile_expr(fy.expr(), limits, format!("records.{name}.fields.{fnm}"))?,
                yaml: match fy {
                    crate::mapping::FieldYaml::Short(s) => {
                        crate::mapping::FieldYaml::Short(s.clone())
                    }
                    crate::mapping::FieldYaml::Long {
                        expr,
                        required,
                        on_error,
                        default,
                    } => crate::mapping::FieldYaml::Long {
                        expr: expr.clone(),
                        required: *required,
                        on_error: on_error.clone(),
                        default: default.clone(),
                    },
                },
            });
        }
        records.push(CompiledRecord {
            name: name.clone(),
            emit,
            foreach,
            r#as: rec.r#as.clone(),
            when,
            vars,
            fields,
        });
    }

    let mut validations = Vec::new();
    for (i, v) in doc.validations.iter().enumerate() {
        all_expressions.push(v.expr.clone());
        validations.push(CompiledValidation {
            path: format!("validations[{i}]"),
            cel: compile_expr(&v.expr, limits, format!("validations[{i}]"))?,
            message: v.message.clone(),
        });
    }

    Ok(CompiledMapping {
        name: doc.name,
        version: doc.version,
        error_mode,
        records,
        validations,
        all_expressions,
        code_systems: reg,
    })
}

pub(crate) fn compile_expr(
    src: &str,
    limits: &SecurityLimits,
    path: String,
) -> Result<CompiledCel, CompileError> {
    crosswalk_cel::compile_expr(src, limits, path)
}
