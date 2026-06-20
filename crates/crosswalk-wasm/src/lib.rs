use crosswalk_core::{
    ErrorCode, ErrorSeverity, EvaluationInput, ExpressionIssue, ExpressionPhase,
    ExpressionPreviewResult, MappingRuntime, PrivacyMode, PublicSchemaDirection,
    PublicSchemaEvaluateOptions, PublicSchemaEvaluationInput, RuntimeOptions, SecurityLimits,
};
use serde_json::json;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmMappingRuntime {
    inner: MappingRuntime,
}

impl Default for WasmMappingRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmMappingRuntime {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: MappingRuntime::new(RuntimeOptions::default()),
        }
    }

    /// Replace evaluation limits from a JSON object (all fields of `SecurityLimits`).
    /// Returns `{"ok":true}` or `{"error":"..."}`.
    pub fn set_limits_json(&mut self, json: &str) -> String {
        match serde_json::from_str::<SecurityLimits>(json) {
            Ok(l) => {
                // Clamp caller-supplied limits to the secure `[floor, ceiling]` ranges so a
                // malicious caller (e.g. via XSS / a hostile plugin) cannot WIDEN limits beyond
                // their defaults to defeat the DoS protections, nor zero them out.
                self.inner.limits = l.clamped();
                json!({ "ok": true }).to_string()
            }
            Err(e) => json!({ "error": e.to_string() }).to_string(),
        }
    }

    /// Replace host `RuntimeOptions` from JSON (`timezone`, `locale`, `max_expression_cost`, `default_errors_mode`).
    pub fn set_runtime_options_json(&mut self, json: &str) -> String {
        match serde_json::from_str::<RuntimeOptions>(json) {
            Ok(o) => {
                self.inner.options = o;
                json!({ "ok": true }).to_string()
            }
            Err(e) => json!({ "error": e.to_string() }).to_string(),
        }
    }

    /// Returns JSON `{ "name": "..." }` on success or `{ "error": "..." }` on failure.
    pub fn compile_mapping_meta(&self, yaml: &str) -> String {
        match self.inner.compile_mapping(yaml) {
            Ok(c) => json!({ "name": c.name, "version": c.version }).to_string(),
            Err(e) => json!({ "error": e.to_string() }).to_string(),
        }
    }

    /// Evaluate mapping YAML against JSON `source` and JSON `ctx`.
    pub fn evaluate_json(&self, mapping_yaml: &str, source_json: &str, ctx_json: &str) -> String {
        let compiled = match self.inner.compile_mapping(mapping_yaml) {
            Ok(c) => c,
            Err(e) => return json!({ "errors": [{"message": e.to_string()}] }).to_string(),
        };
        let source: serde_json::Value = match serde_json::from_str(source_json) {
            Ok(v) => v,
            Err(e) => return json!({ "errors": [{"message": e.to_string()}] }).to_string(),
        };
        let ctx: serde_json::Value = serde_json::from_str(ctx_json).unwrap_or(json!({}));
        let out = self.inner.evaluate(
            &compiled,
            EvaluationInput {
                source,
                context: ctx,
            },
        );
        json!({
            "records": out.records,
            "warnings": out.warnings,
            "errors": out.errors,
        })
        .to_string()
    }

    /// Compile PublicSchema v0.2 mapping YAML/JSON and return metadata.
    pub fn compile_publicschema_mapping_meta(&self, mapping: &str) -> String {
        match self
            .inner
            .compile_publicschema_mapping(mapping, Default::default())
        {
            Ok(c) => serde_json::to_string(&c.meta)
                .unwrap_or_else(|e| json!({ "error": e.to_string() }).to_string()),
            Err(e) => json!({ "error": e.to_string() }).to_string(),
        }
    }

    /// Evaluate a PublicSchema v0.2 mapping document against JSON `source` and JSON `ctx`.
    pub fn evaluate_publicschema_json(
        &self,
        mapping: &str,
        source_json: &str,
        ctx_json: &str,
        direction: &str,
        errors_mode: &str,
        privacy: &str,
    ) -> String {
        let compiled = match self
            .inner
            .compile_publicschema_mapping(mapping, Default::default())
        {
            Ok(c) => c,
            Err(e) => return json!({ "ok": false, "output": {}, "log": [], "warnings": [], "errors": [{"message": e.to_string()}] }).to_string(),
        };
        let source: serde_json::Value = match serde_json::from_str(source_json) {
            Ok(v) => v,
            Err(e) => return json!({ "ok": false, "output": {}, "log": [], "warnings": [], "errors": [{"message": format!("source_json: {e}")}] }).to_string(),
        };
        let ctx: serde_json::Value = serde_json::from_str(ctx_json).unwrap_or(json!({}));
        let direction = match parse_publicschema_direction(direction) {
            Ok(d) => d,
            Err(msg) => return json!({ "ok": false, "output": {}, "log": [], "warnings": [], "errors": [{"message": msg}] }).to_string(),
        };
        let out = self.inner.evaluate_publicschema_mapping(
            &compiled,
            PublicSchemaEvaluationInput {
                source,
                context: ctx,
                options: PublicSchemaEvaluateOptions {
                    direction,
                    errors_mode: if errors_mode.is_empty() {
                        None
                    } else {
                        Some(errors_mode.to_string())
                    },
                    privacy: parse_privacy_mode(privacy),
                },
            },
        );
        serde_json::to_string(&out)
            .unwrap_or_else(|e| json!({ "ok": false, "output": {}, "log": [], "warnings": [], "errors": [{"message": e.to_string()}] }).to_string())
    }

    /// Evaluate one mapping-stdlib CEL expression (no mapping YAML). `source_json` / `ctx_json` are JSON values.
    /// Returns `{"ok":true,"value":...}` on success, or `{"ok":false,"error":"..."}` (invalid `source_json` or CEL failure).
    pub fn evaluate_expression_json(
        &self,
        expr: &str,
        source_json: &str,
        ctx_json: &str,
    ) -> String {
        let source: serde_json::Value = match serde_json::from_str(source_json) {
            Ok(v) => v,
            Err(e) => {
                return json!({"ok": false, "error": format!("source_json: {e}")}).to_string();
            }
        };
        let ctx: serde_json::Value = serde_json::from_str(ctx_json).unwrap_or(json!({}));
        match self.inner.evaluate_cel_expression(
            expr,
            EvaluationInput {
                source,
                context: ctx,
            },
        ) {
            Ok(v) => json!({"ok": true, "value": v}).to_string(),
            Err(e) => json!({"ok": false, "error": e.to_string()}).to_string(),
        }
    }

    /// Editor-oriented: preview a single PublicSchema property-mapping rule expression.
    /// `rule_json`: a JSON object matching the property_mapping shape (`source`, `target`, `formula`, …).
    /// `source_json`: the sample record JSON.
    /// `options_json`: optional `{"direction":"to_target","context":{…}}`.
    /// Returns the same JSON shape as `preview_expression_json` (`ExpressionPreviewResult`), or
    /// `{"error":"…"}` when `rule_json` / `source_json` cannot be parsed.
    pub fn preview_publicschema_rule_expression_json(
        &self,
        rule_json: &str,
        source_json: &str,
        options_json: &str,
    ) -> String {
        let rule: serde_json::Value = match serde_json::from_str(rule_json) {
            Ok(v) => v,
            Err(e) => return json!({ "error": format!("rule_json: {e}") }).to_string(),
        };
        let source: serde_json::Value = match serde_json::from_str(source_json) {
            Ok(v) => v,
            Err(e) => return json!({ "error": format!("source_json: {e}") }).to_string(),
        };
        let opts: serde_json::Value = serde_json::from_str(options_json).unwrap_or(json!({}));
        let direction_str = opts
            .get("direction")
            .and_then(|v| v.as_str())
            .unwrap_or("to_target");
        let direction = match parse_publicschema_direction(direction_str) {
            Ok(d) => d,
            Err(msg) => return json!({ "error": msg }).to_string(),
        };
        let ctx = opts.get("context").cloned().unwrap_or(json!({}));
        let r = self
            .inner
            .preview_publicschema_rule_expression(&rule, source, direction, ctx);
        serde_json::to_string(&r).unwrap_or_else(|e| json!({ "error": e.to_string() }).to_string())
    }

    /// Returns the helper-function registry metadata as JSON.
    /// Shape: `{"version":"builtin","helpers":[…]}` where each entry has at minimum `{"name":"…"}`.
    pub fn get_publicschema_helper_metadata(&self) -> String {
        let helpers: Vec<serde_json::Value> = crosswalk_core::helper_metadata()
            .into_iter()
            .map(|helper| json!({ "name": helper.name }))
            .collect();
        json!({
            "version": "builtin",
            "helpers": helpers,
        })
        .to_string()
    }

    /// Editor-oriented: structured preview (same JSON shape as Rust `ExpressionPreviewResult`).
    /// Invalid `source_json` yields a result with a single `issues` entry; bad `ctx_json` falls back to `{}`.
    pub fn preview_expression_json(&self, expr: &str, source_json: &str, ctx_json: &str) -> String {
        let source: serde_json::Value = match serde_json::from_str(source_json) {
            Ok(v) => v,
            Err(e) => {
                let r = ExpressionPreviewResult::from_parts(
                    expr.to_string(),
                    None,
                    vec![ExpressionIssue {
                        phase: ExpressionPhase::Evaluation,
                        severity: ErrorSeverity::Error,
                        code: ErrorCode::ValidationError,
                        message: format!("source_json: {e}"),
                        line: None,
                        column: None,
                        expression: expr.to_string(),
                        source_path: None,
                    }],
                );
                return serde_json::to_string(&r).expect("serialize preview");
            }
        };
        let ctx: serde_json::Value = serde_json::from_str(ctx_json).unwrap_or(json!({}));
        let r = self.inner.preview_cel_expression(
            expr,
            EvaluationInput {
                source,
                context: ctx,
            },
        );
        serde_json::to_string(&r).expect("serialize preview")
    }
}

fn parse_publicschema_direction(direction: &str) -> Result<PublicSchemaDirection, String> {
    match direction {
        "to_target" | "to-target" | "forward" => Ok(PublicSchemaDirection::ToTarget),
        "from_target" | "from-target" | "reverse" => Ok(PublicSchemaDirection::FromTarget),
        other => Err(format!(
            "direction: expected to_target or from_target, got {other}"
        )),
    }
}

fn parse_privacy_mode(privacy: &str) -> PrivacyMode {
    match privacy {
        "authoring" => PrivacyMode::Authoring,
        "debug" => PrivacyMode::Debug,
        _ => PrivacyMode::Production,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_limits_json_clamps_overwide_values() {
        let mut rt = WasmMappingRuntime::new();
        // Caller attempts to widen output/list limits far beyond the secure defaults.
        let out = rt.set_limits_json(
            r#"{"max_expression_bytes":262144,"max_output_json_bytes":18446744073709551615,"max_list_len":18446744073709551615,"max_string_bytes":1048576,"max_eval_steps":1000000}"#,
        );
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], true);
        // Clamped down to the defaults (the hard ceilings).
        assert_eq!(rt.inner.limits.max_output_json_bytes, 16 * 1024 * 1024);
        assert_eq!(rt.inner.limits.max_list_len, 100_000);
    }

    #[test]
    fn evaluate_expression_json_ok() {
        let rt = WasmMappingRuntime::new();
        let out = rt.evaluate_expression_json("1 + 2", "{}", "{}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["value"], 3);
    }

    #[test]
    fn evaluate_expression_json_bad_source() {
        let rt = WasmMappingRuntime::new();
        let out = rt.evaluate_expression_json("1", "not-json", "{}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("source_json"));
    }

    #[test]
    fn preview_expression_json_syntax_issue() {
        let rt = WasmMappingRuntime::new();
        let out = rt.preview_expression_json("1 +++", "{}", "{}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let issues = v["issues"].as_array().unwrap();
        assert!(!issues.is_empty());
        assert_eq!(issues[0]["phase"], "syntax");
    }

    #[test]
    fn preview_expression_json_bad_source_is_issue_not_panic() {
        let rt = WasmMappingRuntime::new();
        let out = rt.preview_expression_json("1 + 1", "{", "{}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["author_expression"], "1 + 1");
        let issues = v["issues"].as_array().unwrap();
        assert_eq!(issues[0]["phase"], "evaluation");
    }

    #[test]
    fn parse_publicschema_direction_rejects_invalid() {
        assert!(parse_publicschema_direction("bogus").is_err());
        assert!(parse_publicschema_direction("ToTarget").is_err());
        assert!(parse_publicschema_direction("to_target").is_ok());
        assert!(parse_publicschema_direction("from_target").is_ok());
        assert!(parse_publicschema_direction("forward").is_ok());
        assert!(parse_publicschema_direction("reverse").is_ok());
    }

    #[test]
    fn evaluate_publicschema_json_bad_direction_returns_error() {
        let rt = WasmMappingRuntime::new();
        let mapping = r#"{"version":"0.2","property_mappings":[{"source":"/a","target":"/b"}]}"#;
        let out = rt.evaluate_publicschema_json(mapping, "{}", "{}", "bad_dir", "", "production");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], false);
        let errors = v["errors"].as_array().unwrap();
        assert!(!errors.is_empty());
    }

    #[test]
    fn compile_publicschema_mapping_meta_returns_hash_status() {
        let rt = WasmMappingRuntime::new();
        let mapping = r#"{"version":"0.2","property_mappings":[{"source":"/a","target":"/b"}]}"#;
        let out = rt.compile_publicschema_mapping_meta(mapping);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_none(), "unexpected error: {v}");
        assert_eq!(v["hash_status"], "canonical");
        assert!(!v["deterministic_hash"].as_str().unwrap().is_empty());
    }

    #[test]
    fn get_publicschema_helper_metadata_shape() {
        let rt = WasmMappingRuntime::new();
        let out = rt.get_publicschema_helper_metadata();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["version"], "builtin");
        let helpers = v["helpers"].as_array().unwrap();
        assert!(!helpers.is_empty());
        assert!(helpers.iter().any(|h| h["name"] == "present"));
        assert!(helpers.iter().any(|h| h["name"] == "text_lower"));
    }

    #[test]
    fn preview_publicschema_rule_expression_json_bad_rule_returns_error() {
        let rt = WasmMappingRuntime::new();
        let out = rt.preview_publicschema_rule_expression_json("not-json", "{}", "{}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v["error"].as_str().unwrap().contains("rule_json"));
    }

    #[test]
    fn preview_publicschema_rule_expression_json_ok() {
        let rt = WasmMappingRuntime::new();
        let rule = r#"{"source":"/name","target":"/full_name","formula":"source"}"#;
        let source = r#"{"name":"Alice"}"#;
        let out = rt.preview_publicschema_rule_expression_json(rule, source, "{}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        // No error key; should have the ExpressionPreviewResult shape.
        assert!(v.get("error").is_none(), "unexpected error: {v}");
        assert!(v.get("author_expression").is_some() || v.get("issues").is_some());
    }
}
