use crate::budget::BudgetGuard;
use crate::code_system::{CodeSystemError, CodeSystemRegistry};
use crate::compiled::CompiledMapping;
use crate::compiler::compile_mapping_yaml;
use crate::errors::{CompileError, ExpressionPreviewResult, StandaloneEvalError};
use crate::eval_ctx::{clear_eval_ctx, clear_warnings, set_eval_ctx, take_warnings};
use crate::evaluator::{
    evaluate_cel_expression, evaluate_cel_expression_with_input, evaluate_mapping_with_limits,
    StandaloneExpressionInput,
};
use crate::publicschema::{
    CompiledPublicSchemaMapping, PublicSchemaCompileOptions, PublicSchemaDirection,
    PublicSchemaEvaluationInput, PublicSchemaTransformOutput,
};
use crate::security::SecurityLimits;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuntimeOptions {
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub locale: Option<String>,
    /// Reserved: `cel` 0.13 has no execution cost hook wired to `Program::execute`.
    #[serde(default)]
    pub max_expression_cost: Option<u64>,
    /// When the mapping YAML omits `errors.mode`, this string is parsed like the YAML value
    /// (`strict`, `collect`, `lenient`). If this is also unset, the compiler defaults to strict.
    /// When YAML sets `errors.mode`, that value always wins.
    #[serde(default)]
    pub default_errors_mode: Option<String>,
}

pub struct MappingRuntime {
    pub options: RuntimeOptions,
    pub limits: SecurityLimits,
    code_systems: CodeSystemRegistry,
}

#[derive(Debug, Clone)]
pub struct EvaluationInput {
    pub source: JsonValue,
    pub context: JsonValue,
}

#[derive(Debug, Clone, Serialize)]
pub struct MappingOutput {
    pub records: BTreeMap<String, Vec<JsonValue>>,
    pub warnings: Vec<crate::errors::MappingError>,
    pub errors: Vec<crate::errors::MappingError>,
}

impl MappingRuntime {
    /// Clone of the runtime code-system registry (merged into each `compile_mapping` call).
    pub fn code_systems_clone(&self) -> CodeSystemRegistry {
        self.code_systems.clone()
    }

    pub fn new(options: RuntimeOptions) -> Self {
        let mut code_systems = CodeSystemRegistry::new();
        crate::iso_systems::load_iso_systems(&mut code_systems);
        Self {
            options,
            limits: SecurityLimits::default(),
            code_systems,
        }
    }

    /// Reserved for future host-registered functions; the mapping stdlib is always installed per evaluation.
    pub fn register_standard_functions(&mut self) {}

    pub fn register_code_system(
        &mut self,
        name: &str,
        raw: &serde_yaml::Value,
    ) -> Result<(), CodeSystemError> {
        crate::code_system::merge_yaml_value(&mut self.code_systems, name, raw)
    }

    pub fn compile_mapping(&self, yaml: &str) -> Result<CompiledMapping, CompileError> {
        compile_mapping_yaml(
            yaml,
            &self.limits,
            self.code_systems.clone(),
            self.options.default_errors_mode.as_deref(),
        )
    }

    pub fn compile_publicschema_mapping(
        &self,
        text: &str,
        options: PublicSchemaCompileOptions,
    ) -> Result<CompiledPublicSchemaMapping, CompileError> {
        crate::publicschema::compile_publicschema_mapping(
            text,
            &self.limits,
            self.code_systems.clone(),
            self.options.default_errors_mode.as_deref(),
            options,
        )
    }

    pub fn evaluate_publicschema_mapping(
        &self,
        mapping: &CompiledPublicSchemaMapping,
        mut input: PublicSchemaEvaluationInput,
    ) -> PublicSchemaTransformOutput {
        if let JsonValue::Object(ref mut m) = input.context {
            if let Some(tz) = &self.options.timezone {
                m.entry("timezone".to_string())
                    .or_insert_with(|| JsonValue::String(tz.clone()));
            }
            if let Some(loc) = &self.options.locale {
                m.entry("locale".to_string())
                    .or_insert_with(|| JsonValue::String(loc.clone()));
            }
        }
        crate::publicschema::evaluate_publicschema_mapping(mapping, input)
    }

    pub fn preview_publicschema_rule_expression(
        &self,
        mapping_rule: &JsonValue,
        sample_record: JsonValue,
        direction: PublicSchemaDirection,
        ctx: JsonValue,
    ) -> ExpressionPreviewResult {
        crate::publicschema::preview_publicschema_rule_expression(
            mapping_rule,
            sample_record,
            direction,
            ctx,
            &self.limits,
            Arc::new(self.code_systems.clone()),
        )
    }

    pub fn evaluate(&self, mapping: &CompiledMapping, input: EvaluationInput) -> MappingOutput {
        clear_warnings();
        let mut ctx = match input.context {
            JsonValue::Object(m) => JsonValue::Object(m),
            JsonValue::Null => JsonValue::Object(Default::default()),
            other => JsonValue::Object(serde_json::Map::from_iter([("value".to_string(), other)])),
        };
        if let JsonValue::Object(ref mut m) = ctx {
            if let Some(tz) = &self.options.timezone {
                m.entry("timezone".to_string())
                    .or_insert_with(|| JsonValue::String(tz.clone()));
            }
            if let Some(loc) = &self.options.locale {
                m.entry("locale".to_string())
                    .or_insert_with(|| JsonValue::String(loc.clone()));
            }
        }
        set_eval_ctx(ctx.clone());
        let _budget = BudgetGuard::install(Arc::new(self.limits.clone()));
        let mut out = evaluate_mapping_with_limits(mapping, input.source, ctx, &self.limits);
        drop(_budget);
        clear_eval_ctx();
        if let Err(msg) = self.limits.check_output_records(&out.records) {
            out.errors.push(crate::errors::MappingError::error(
                crate::errors::ErrorCode::InternalError,
                msg,
                Some("output.records".into()),
                None,
            ));
            out.records.clear();
        }
        for w in take_warnings() {
            out.warnings.push(crate::errors::MappingError {
                code: crate::errors::ErrorCode::ValidationError,
                message: w,
                path: None,
                expression: None,
                source_path: None,
                record: None,
                index: None,
                severity: crate::errors::ErrorSeverity::Warning,
            });
        }
        out
    }

    /// Evaluate a single mapping-stdlib CEL expression (no mapping YAML).
    ///
    /// Same `source` / `context` JSON shape and host `ctx` defaults (timezone, locale) as [`Self::evaluate`].
    pub fn evaluate_cel_expression(
        &self,
        expr: &str,
        input: EvaluationInput,
    ) -> Result<JsonValue, StandaloneEvalError> {
        clear_warnings();
        let mut ctx = match input.context {
            JsonValue::Object(m) => JsonValue::Object(m),
            JsonValue::Null => JsonValue::Object(Default::default()),
            other => JsonValue::Object(serde_json::Map::from_iter([("value".to_string(), other)])),
        };
        if let JsonValue::Object(ref mut m) = ctx {
            if let Some(tz) = &self.options.timezone {
                m.entry("timezone".to_string())
                    .or_insert_with(|| JsonValue::String(tz.clone()));
            }
            if let Some(loc) = &self.options.locale {
                m.entry("locale".to_string())
                    .or_insert_with(|| JsonValue::String(loc.clone()));
            }
        }
        set_eval_ctx(ctx.clone());
        let _budget = BudgetGuard::install(Arc::new(self.limits.clone()));
        let codes = Arc::new(self.code_systems.clone());
        let out = evaluate_cel_expression(expr, input.source, ctx, &self.limits, codes);
        drop(_budget);
        clear_eval_ctx();
        let _ = take_warnings();
        out
    }

    /// Evaluate a single mapping-stdlib CEL expression against arbitrary root bindings.
    pub fn evaluate_cel_expression_with_input(
        &self,
        expr: &str,
        mut input: StandaloneExpressionInput,
    ) -> Result<JsonValue, StandaloneEvalError> {
        clear_warnings();
        let ctx = self.prepare_standalone_context(&mut input);
        set_eval_ctx(ctx);
        let _budget = BudgetGuard::install(Arc::new(self.limits.clone()));
        let codes = Arc::new(self.code_systems.clone());
        let out = evaluate_cel_expression_with_input(expr, input, &self.limits, codes);
        drop(_budget);
        clear_eval_ctx();
        let _ = take_warnings();
        out
    }

    /// Like [`Self::evaluate_cel_expression`], but always returns an [`ExpressionPreviewResult`]
    /// with structured issues (syntax **line/column** from `cel`, evaluation errors, limits).
    pub fn preview_cel_expression(
        &self,
        expr: &str,
        input: EvaluationInput,
    ) -> ExpressionPreviewResult {
        clear_warnings();
        let mut ctx = match input.context {
            JsonValue::Object(m) => JsonValue::Object(m),
            JsonValue::Null => JsonValue::Object(Default::default()),
            other => JsonValue::Object(serde_json::Map::from_iter([("value".to_string(), other)])),
        };
        if let JsonValue::Object(ref mut m) = ctx {
            if let Some(tz) = &self.options.timezone {
                m.entry("timezone".to_string())
                    .or_insert_with(|| JsonValue::String(tz.clone()));
            }
            if let Some(loc) = &self.options.locale {
                m.entry("locale".to_string())
                    .or_insert_with(|| JsonValue::String(loc.clone()));
            }
        }
        set_eval_ctx(ctx.clone());
        let _budget = BudgetGuard::install(Arc::new(self.limits.clone()));
        let codes = Arc::new(self.code_systems.clone());
        let out =
            crate::evaluator::preview_cel_expression(expr, input.source, ctx, &self.limits, codes);
        drop(_budget);
        clear_eval_ctx();
        let _ = take_warnings();
        out
    }

    /// Like [`Self::evaluate_cel_expression_with_input`], but returns structured preview
    /// diagnostics instead of `Err`.
    pub fn preview_cel_expression_with_input(
        &self,
        expr: &str,
        mut input: StandaloneExpressionInput,
    ) -> ExpressionPreviewResult {
        clear_warnings();
        let ctx = self.prepare_standalone_context(&mut input);
        set_eval_ctx(ctx);
        let _budget = BudgetGuard::install(Arc::new(self.limits.clone()));
        let codes = Arc::new(self.code_systems.clone());
        let out =
            crate::evaluator::preview_cel_expression_with_input(expr, input, &self.limits, codes);
        drop(_budget);
        clear_eval_ctx();
        let _ = take_warnings();
        out
    }

    fn prepare_standalone_context(&self, input: &mut StandaloneExpressionInput) -> JsonValue {
        let raw_ctx = input
            .root_bindings
            .remove("ctx")
            .unwrap_or_else(|| JsonValue::Object(Default::default()));
        let mut ctx = match raw_ctx {
            JsonValue::Object(m) => JsonValue::Object(m),
            JsonValue::Null => JsonValue::Object(Default::default()),
            other => JsonValue::Object(serde_json::Map::from_iter([("value".to_string(), other)])),
        };
        if let JsonValue::Object(ref mut m) = ctx {
            if let Some(tz) = &self.options.timezone {
                m.entry("timezone".to_string())
                    .or_insert_with(|| JsonValue::String(tz.clone()));
            }
            if let Some(loc) = &self.options.locale {
                m.entry("locale".to_string())
                    .or_insert_with(|| JsonValue::String(loc.clone()));
            }
        }
        input.root_bindings.insert("ctx".to_string(), ctx.clone());
        ctx
    }
}
