//! PyO3 extension `crosswalk`.
#![allow(clippy::useless_conversion)] // `#[pymethods]` expands redundant `Into` for `PyErr` in `?`

use crosswalk_core::{
    CompileError, CompiledMapping, EvaluationInput, ExpressionPreviewResult, MappingOutput,
    MappingRuntime, PrivacyMode, PublicSchemaDirection, PublicSchemaEvaluateOptions,
    PublicSchemaEvaluationInput, PublicSchemaTransformOutput, RuntimeOptions, SecurityLimits,
    StandaloneEvalError,
};
use pyo3::create_exception;
use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use pythonize::{depythonize, pythonize};
use std::sync::Arc;

create_exception!(
    crosswalk,
    MappingCompileError,
    pyo3::exceptions::PyException
);

fn py_compile_err(e: CompileError) -> PyErr {
    let msg = match &e {
        CompileError::Cel {
            path,
            expression,
            message,
        } => {
            format!("CEL compile error at {path}: {message}\nexpression: {expression}")
        }
        _ => e.to_string(),
    };
    MappingCompileError::new_err(msg)
}

fn py_standalone_eval_err(e: StandaloneEvalError) -> PyErr {
    match e {
        StandaloneEvalError::Compile(c) => py_compile_err(c),
        StandaloneEvalError::InvalidBindingName { name, message } => {
            PyTypeError::new_err(format!("invalid root binding name `{name}`: {message}"))
        }
        StandaloneEvalError::Evaluate {
            message,
            expression,
        } => PyRuntimeError::new_err(format!("{message}\nexpression: {expression}")),
    }
}

fn runtime_options_from_any(val: &Bound<'_, PyAny>) -> PyResult<RuntimeOptions> {
    if val.is_none() {
        return Ok(RuntimeOptions::default());
    }
    if let Ok(s) = val.extract::<&str>() {
        let t = s.trim();
        if t.is_empty() {
            return Ok(RuntimeOptions::default());
        }
        return serde_json::from_str(t).map_err(|e| {
            PyTypeError::new_err(format!("runtime_options: invalid JSON string ({e})"))
        });
    }
    depythonize(val).map_err(|e| {
        PyTypeError::new_err(format!(
            "runtime_options: expected dict or JSON string ({e})"
        ))
    })
}

fn security_limits_from_any(val: &Bound<'_, PyAny>) -> PyResult<SecurityLimits> {
    if let Ok(s) = val.extract::<&str>() {
        return serde_json::from_str(s.trim())
            .map(SecurityLimits::clamped)
            .map_err(|e| PyTypeError::new_err(format!("limits: invalid JSON string ({e})")));
    }
    depythonize(val)
        .map(SecurityLimits::clamped)
        .map_err(|e| PyTypeError::new_err(format!("limits: expected dict or JSON string ({e})")))
}

/// `source` / `context`: `dict` or JSON `str`. `context` may be omitted / `None` for `{}`.
fn json_value_from_any(name: &str, val: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    if val.is_none() {
        return Err(PyTypeError::new_err(format!("{name} cannot be None")));
    }
    if let Ok(s) = val.extract::<&str>() {
        return serde_json::from_str(s)
            .map_err(|e| PyTypeError::new_err(format!("{name}: invalid JSON string ({e})")));
    }
    depythonize(val)
        .map_err(|e| PyTypeError::new_err(format!("{name}: expected dict or JSON string ({e})")))
}

fn json_value_from_any_or_empty_context(
    val: Option<Bound<'_, PyAny>>,
) -> PyResult<serde_json::Value> {
    match val {
        None => Ok(serde_json::json!({})),
        Some(o) if o.is_none() => Ok(serde_json::json!({})),
        Some(o) => {
            if let Ok(s) = o.extract::<&str>() {
                let t = s.trim();
                if t.is_empty() {
                    return Ok(serde_json::json!({}));
                }
                return serde_json::from_str(t).map_err(|e| {
                    PyTypeError::new_err(format!("context: invalid JSON string ({e})"))
                });
            }
            depythonize(&o).map_err(|e| {
                PyTypeError::new_err(format!("context: expected dict or JSON string ({e})"))
            })
        }
    }
}

fn mapping_output_to_py(py: Python<'_>, out: MappingOutput) -> PyResult<Py<PyAny>> {
    let v = serde_json::json!({
        "records": out.records,
        "warnings": out.warnings,
        "errors": out.errors,
    });
    pythonize(py, &v)
        .map_err(|e| PyTypeError::new_err(e.to_string()))
        .map(|b| b.unbind())
}

fn mapping_output_to_json_string(out: MappingOutput) -> PyResult<String> {
    serde_json::to_string(&serde_json::json!({
        "records": out.records,
        "warnings": out.warnings,
        "errors": out.errors,
    }))
    .map_err(|e| PyTypeError::new_err(e.to_string()))
}

fn publicschema_output_to_py(
    py: Python<'_>,
    out: PublicSchemaTransformOutput,
) -> PyResult<Py<PyAny>> {
    pythonize(py, &out)
        .map_err(|e| PyTypeError::new_err(e.to_string()))
        .map(|b| b.unbind())
}

fn publicschema_output_to_json_string(out: PublicSchemaTransformOutput) -> PyResult<String> {
    serde_json::to_string(&out).map_err(|e| PyTypeError::new_err(e.to_string()))
}

fn publicschema_direction_from_str(direction: Option<&str>) -> PyResult<PublicSchemaDirection> {
    match direction.unwrap_or("to_target") {
        "to_target" | "to-target" | "forward" => Ok(PublicSchemaDirection::ToTarget),
        "from_target" | "from-target" | "reverse" => Ok(PublicSchemaDirection::FromTarget),
        other => Err(PyTypeError::new_err(format!(
            "direction: expected to_target or from_target, got {other}"
        ))),
    }
}

fn privacy_mode_from_str(privacy: Option<&str>) -> PyResult<PrivacyMode> {
    match privacy.unwrap_or("production") {
        "production" => Ok(PrivacyMode::Production),
        "authoring" => Ok(PrivacyMode::Authoring),
        "debug" => Ok(PrivacyMode::Debug),
        other => Err(PyTypeError::new_err(format!(
            "privacy: expected production, authoring, or debug, got {other}"
        ))),
    }
}

#[pyclass(name = "CompiledMapping")]
pub struct PyCompiledMapping {
    inner: Arc<CompiledMapping>,
}

#[pyclass(name = "CompiledPublicSchemaMapping")]
pub struct PyCompiledPublicSchemaMapping {
    inner: Arc<crosswalk_core::CompiledPublicSchemaMapping>,
}

#[pymethods]
impl PyCompiledMapping {
    #[getter]
    fn name(&self) -> String {
        self.inner.name.clone()
    }

    #[getter]
    fn version(&self) -> String {
        self.inner.version.clone()
    }
}

#[pymethods]
impl PyCompiledPublicSchemaMapping {
    #[getter]
    fn deterministic_hash(&self) -> String {
        self.inner.meta.deterministic_hash.clone()
    }

    #[getter]
    fn version(&self) -> String {
        self.inner.meta.version.clone()
    }

    fn meta(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        pythonize(py, &self.inner.meta)
            .map_err(|e| PyTypeError::new_err(e.to_string()))
            .map(|b| b.unbind())
    }
}

#[pyclass(name = "MappingRuntime")]
pub struct PyMappingRuntime {
    inner: MappingRuntime,
}

#[pymethods]
impl PyMappingRuntime {
    /// Optional initial `RuntimeOptions` as a **`dict`** (recommended) or a JSON **`str`**.
    #[new]
    #[pyo3(signature = (runtime_options=None))]
    fn new(runtime_options: Option<Bound<'_, PyAny>>) -> PyResult<Self> {
        let options = match runtime_options {
            None => RuntimeOptions::default(),
            Some(o) => runtime_options_from_any(&o)?,
        };
        Ok(Self {
            inner: MappingRuntime::new(options),
        })
    }

    /// Replace limits from a **`dict`** (recommended) or JSON **`str`** (interop).
    fn set_limits(&mut self, limits: Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.limits = security_limits_from_any(&limits)?;
        Ok(())
    }

    /// Replace host runtime options from a **`dict`** or JSON **`str`**.
    fn set_runtime_options(&mut self, options: Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.options = runtime_options_from_any(&options)?;
        Ok(())
    }

    /// Same as [`set_limits`](Self::set_limits); kept for callers that already pass JSON text.
    fn set_limits_json(&mut self, json: &str) -> PyResult<()> {
        let lim: SecurityLimits = serde_json::from_str(json)
            .map_err(|e| PyTypeError::new_err(format!("limits: invalid JSON string ({e})")))?;
        self.inner.limits = lim.clamped();
        Ok(())
    }

    /// Same as [`set_runtime_options`](Self::set_runtime_options).
    fn set_runtime_options_json(&mut self, json: &str) -> PyResult<()> {
        let o: RuntimeOptions = serde_json::from_str(json).map_err(|e| {
            PyTypeError::new_err(format!("runtime options: invalid JSON string ({e})"))
        })?;
        self.inner.options = o;
        Ok(())
    }

    /// Register a code system from YAML **`str`** or a **`dict`** (converted via JSON → YAML value).
    fn register_code_system(&mut self, name: &str, spec: Bound<'_, PyAny>) -> PyResult<()> {
        let yaml_val: serde_yaml::Value = if let Ok(s) = spec.extract::<&str>() {
            serde_yaml::from_str(s).map_err(|e| {
                PyTypeError::new_err(format!("code system {name}: invalid YAML ({e})"))
            })?
        } else {
            let j: serde_json::Value = depythonize(&spec).map_err(|e| {
                PyTypeError::new_err(format!(
                    "code system {name}: expected str YAML or dict ({e})"
                ))
            })?;
            serde_yaml::to_value(&j).map_err(|e| {
                PyTypeError::new_err(format!("code system {name}: could not convert dict ({e})"))
            })?
        };
        self.inner
            .register_code_system(name, &yaml_val)
            .map_err(|e| PyTypeError::new_err(e.to_string()))
    }

    /// Compile mapping YAML once; reuse with [`evaluate_compiled`](Self::evaluate_compiled).
    fn compile_mapping(&self, py: Python<'_>, yaml: &str) -> PyResult<Py<PyCompiledMapping>> {
        let c = self.inner.compile_mapping(yaml).map_err(py_compile_err)?;
        Py::new(py, PyCompiledMapping { inner: Arc::new(c) })
    }

    /// Compile a PublicSchema v0.2 mapping document (YAML or JSON) once.
    fn compile_publicschema_mapping(
        &self,
        py: Python<'_>,
        mapping: &str,
    ) -> PyResult<Py<PyCompiledPublicSchemaMapping>> {
        let c = self
            .inner
            .compile_publicschema_mapping(mapping, Default::default())
            .map_err(py_compile_err)?;
        Py::new(py, PyCompiledPublicSchemaMapping { inner: Arc::new(c) })
    }

    /// Evaluate a compiled mapping. `source` and optional `context` are **`dict`** or JSON **`str`**.
    /// Returns `{"records": ..., "warnings": ..., "errors": ...}`.
    #[pyo3(signature = (compiled, source, context=None))]
    fn evaluate_compiled(
        &self,
        py: Python<'_>,
        compiled: &Bound<'_, PyCompiledMapping>,
        source: Bound<'_, PyAny>,
        context: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let mapping = compiled.borrow().inner.clone();
        let src = json_value_from_any("source", &source)?;
        let ctx = json_value_from_any_or_empty_context(context)?;
        let out = self.inner.evaluate(
            &mapping,
            EvaluationInput {
                source: src,
                context: ctx,
            },
        );
        mapping_output_to_py(py, out)
    }

    /// Same as [`evaluate_compiled`](Self::evaluate_compiled) but returns a JSON string (WASM/interop parity).
    #[pyo3(signature = (compiled, source_json, ctx_json))]
    fn evaluate_compiled_json(
        &self,
        compiled: &Bound<'_, PyCompiledMapping>,
        source_json: &str,
        ctx_json: &str,
    ) -> PyResult<String> {
        let mapping = compiled.borrow().inner.clone();
        let source: serde_json::Value = serde_json::from_str(source_json)
            .map_err(|e| PyTypeError::new_err(format!("source_json: invalid JSON ({e})")))?;
        let ctx: serde_json::Value =
            serde_json::from_str(ctx_json).unwrap_or(serde_json::json!({}));
        let out = self.inner.evaluate(
            &mapping,
            EvaluationInput {
                source,
                context: ctx,
            },
        );
        mapping_output_to_json_string(out)
    }

    /// Evaluate a compiled PublicSchema v0.2 mapping. Returns
    /// {"ok": bool, "output": ..., "log": ..., "warnings": ..., "errors": ...}.
    #[pyo3(signature = (compiled, source, context=None, direction=None, errors_mode=None, privacy=None))]
    #[allow(clippy::too_many_arguments)]
    fn evaluate_publicschema_compiled(
        &self,
        py: Python<'_>,
        compiled: &Bound<'_, PyCompiledPublicSchemaMapping>,
        source: Bound<'_, PyAny>,
        context: Option<Bound<'_, PyAny>>,
        direction: Option<&str>,
        errors_mode: Option<String>,
        privacy: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let mapping = compiled.borrow().inner.clone();
        let src = json_value_from_any("source", &source)?;
        let ctx = json_value_from_any_or_empty_context(context)?;
        let out = self.inner.evaluate_publicschema_mapping(
            &mapping,
            PublicSchemaEvaluationInput {
                source: src,
                context: ctx,
                options: PublicSchemaEvaluateOptions {
                    direction: publicschema_direction_from_str(direction)?,
                    errors_mode,
                    privacy: privacy_mode_from_str(privacy)?,
                },
            },
        );
        publicschema_output_to_py(py, out)
    }

    #[pyo3(signature = (compiled, source_json, ctx_json, direction=None, errors_mode=None, privacy=None))]
    fn evaluate_publicschema_compiled_json(
        &self,
        compiled: &Bound<'_, PyCompiledPublicSchemaMapping>,
        source_json: &str,
        ctx_json: &str,
        direction: Option<&str>,
        errors_mode: Option<String>,
        privacy: Option<&str>,
    ) -> PyResult<String> {
        let mapping = compiled.borrow().inner.clone();
        let source: serde_json::Value = serde_json::from_str(source_json)
            .map_err(|e| PyTypeError::new_err(format!("source_json: invalid JSON ({e})")))?;
        let ctx: serde_json::Value =
            serde_json::from_str(ctx_json).unwrap_or(serde_json::json!({}));
        let out = self.inner.evaluate_publicschema_mapping(
            &mapping,
            PublicSchemaEvaluationInput {
                source,
                context: ctx,
                options: PublicSchemaEvaluateOptions {
                    direction: publicschema_direction_from_str(direction)?,
                    errors_mode,
                    privacy: privacy_mode_from_str(privacy)?,
                },
            },
        );
        publicschema_output_to_json_string(out)
    }

    /// Compile `mapping_yaml` for every call — prefer [`compile_mapping`](Self::compile_mapping) plus
    /// [`evaluate_compiled`](Self::evaluate_compiled) when the mapping is fixed.
    #[pyo3(signature = (mapping_yaml, source, context=None))]
    fn evaluate(
        &self,
        py: Python<'_>,
        mapping_yaml: &str,
        source: Bound<'_, PyAny>,
        context: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let compiled = self
            .inner
            .compile_mapping(mapping_yaml)
            .map_err(py_compile_err)?;
        let src = json_value_from_any("source", &source)?;
        let ctx = json_value_from_any_or_empty_context(context)?;
        let out = self.inner.evaluate(
            &compiled,
            EvaluationInput {
                source: src,
                context: ctx,
            },
        );
        mapping_output_to_py(py, out)
    }

    /// Same as [`evaluate`](Self::evaluate) but takes JSON strings; recompiles every call.
    fn evaluate_json(
        &self,
        mapping_yaml: &str,
        source_json: &str,
        ctx_json: &str,
    ) -> PyResult<String> {
        let compiled = self
            .inner
            .compile_mapping(mapping_yaml)
            .map_err(py_compile_err)?;
        let source: serde_json::Value = serde_json::from_str(source_json)
            .map_err(|e| PyTypeError::new_err(format!("source_json: invalid JSON ({e})")))?;
        let ctx: serde_json::Value =
            serde_json::from_str(ctx_json).unwrap_or(serde_json::json!({}));
        let out = self.inner.evaluate(
            &compiled,
            EvaluationInput {
                source,
                context: ctx,
            },
        );
        mapping_output_to_json_string(out)
    }

    #[pyo3(signature = (mapping, source, context=None, direction=None, errors_mode=None, privacy=None))]
    #[allow(clippy::too_many_arguments)]
    fn evaluate_publicschema(
        &self,
        py: Python<'_>,
        mapping: &str,
        source: Bound<'_, PyAny>,
        context: Option<Bound<'_, PyAny>>,
        direction: Option<&str>,
        errors_mode: Option<String>,
        privacy: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let compiled = self
            .inner
            .compile_publicschema_mapping(mapping, Default::default())
            .map_err(py_compile_err)?;
        let src = json_value_from_any("source", &source)?;
        let ctx = json_value_from_any_or_empty_context(context)?;
        let out = self.inner.evaluate_publicschema_mapping(
            &compiled,
            PublicSchemaEvaluationInput {
                source: src,
                context: ctx,
                options: PublicSchemaEvaluateOptions {
                    direction: publicschema_direction_from_str(direction)?,
                    errors_mode,
                    privacy: privacy_mode_from_str(privacy)?,
                },
            },
        );
        publicschema_output_to_py(py, out)
    }

    #[pyo3(signature = (mapping, source_json, ctx_json, direction=None, errors_mode=None, privacy=None))]
    fn evaluate_publicschema_json(
        &self,
        mapping: &str,
        source_json: &str,
        ctx_json: &str,
        direction: Option<&str>,
        errors_mode: Option<String>,
        privacy: Option<&str>,
    ) -> PyResult<String> {
        let compiled = self
            .inner
            .compile_publicschema_mapping(mapping, Default::default())
            .map_err(py_compile_err)?;
        let source: serde_json::Value = serde_json::from_str(source_json)
            .map_err(|e| PyTypeError::new_err(format!("source_json: invalid JSON ({e})")))?;
        let ctx: serde_json::Value =
            serde_json::from_str(ctx_json).unwrap_or(serde_json::json!({}));
        let out = self.inner.evaluate_publicschema_mapping(
            &compiled,
            PublicSchemaEvaluationInput {
                source,
                context: ctx,
                options: PublicSchemaEvaluateOptions {
                    direction: publicschema_direction_from_str(direction)?,
                    errors_mode,
                    privacy: privacy_mode_from_str(privacy)?,
                },
            },
        );
        publicschema_output_to_json_string(out)
    }

    /// Evaluate a single CEL expression (mapping stdlib, same bindings as a field expression).
    /// No mapping YAML — use for probes, REPL, or glue code. `source` / `context` are dict or JSON str.
    #[pyo3(signature = (expr, source, context=None))]
    fn evaluate_expression(
        &self,
        py: Python<'_>,
        expr: &str,
        source: Bound<'_, PyAny>,
        context: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let src = json_value_from_any("source", &source)?;
        let ctx = json_value_from_any_or_empty_context(context)?;
        let v = self
            .inner
            .evaluate_cel_expression(
                expr,
                EvaluationInput {
                    source: src,
                    context: ctx,
                },
            )
            .map_err(py_standalone_eval_err)?;
        pythonize(py, &v)
            .map_err(|e| PyTypeError::new_err(e.to_string()))
            .map(|b| b.unbind())
    }

    /// Editor-oriented: compile + evaluate one expression; returns a dict with ``author_expression``,
    /// optional ``rewritten_expression`` (CEL input after stdlib namespace rewrite), ``value``, ``issues``,
    /// and ``notes`` (stable hints: syntax positions refer to ``rewritten_expression``; evaluation hints).
    /// Each issue has ``phase`` (`limits` \| `syntax` \| `evaluation`), ``message`` (for syntax, CEL's
    /// multi-line diagnostic when available), optional ``line`` / ``column`` (1-based, refer to
    /// ``rewritten_expression``), ``code``, ``expression`` (same as ``author_expression``), optional ``source_path``.
    #[pyo3(signature = (expr, source, context=None))]
    fn preview_expression(
        &self,
        py: Python<'_>,
        expr: &str,
        source: Bound<'_, PyAny>,
        context: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let src = json_value_from_any("source", &source)?;
        let ctx = json_value_from_any_or_empty_context(context)?;
        let r = self.inner.preview_cel_expression(
            expr,
            EvaluationInput {
                source: src,
                context: ctx,
            },
        );
        preview_result_to_py(py, r)
    }

    /// Return the crosswalk-python crate version (from Cargo.toml at compile time).
    ///
    /// Used by publicschema-build generators to embed a `helper_registry_version`
    /// field in emitted mapping artifacts so consumers know which helper version
    /// compiled and validated the mapping.
    fn helper_registry_version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Preview a single PublicSchema property-mapping rule expression.
    ///
    /// Returns the same ``ExpressionPreviewResult`` shape as ``preview_expression``:
    /// ``author_expression``, ``rewritten_expression``, ``value``, ``issues``, ``notes``.
    ///
    /// ``rule`` is a dict (or JSON str) representing one ``property_mappings`` entry.
    /// ``source`` is a dict or JSON str sample record.
    /// ``direction`` must be ``"to_target"`` (default), ``"from_target"``, or recognised aliases;
    /// unknown strings raise ``TypeError`` (no silent fallback).
    #[pyo3(signature = (rule, source, *, direction=None, context=None))]
    fn preview_publicschema_rule_expression(
        &self,
        py: Python<'_>,
        rule: Bound<'_, PyAny>,
        source: Bound<'_, PyAny>,
        direction: Option<&str>,
        context: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let rule_json = json_value_from_any("rule", &rule)?;
        let src = json_value_from_any("source", &source)?;
        let ctx = json_value_from_any_or_empty_context(context)?;
        let dir = publicschema_direction_from_str(direction)?;
        let r = self
            .inner
            .preview_publicschema_rule_expression(&rule_json, src, dir, ctx);
        preview_result_to_py(py, r)
    }
}

fn preview_result_to_py(py: Python<'_>, r: ExpressionPreviewResult) -> PyResult<Py<PyAny>> {
    pythonize(py, &r)
        .map_err(|e| PyTypeError::new_err(e.to_string()))
        .map(|b| b.unbind())
}

#[pymodule]
fn crosswalk(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyCompiledMapping>()?;
    m.add_class::<PyCompiledPublicSchemaMapping>()?;
    m.add_class::<PyMappingRuntime>()?;
    m.add(
        "MappingCompileError",
        m.py().get_type_bound::<MappingCompileError>(),
    )?;
    Ok(())
}
