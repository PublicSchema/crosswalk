//! Runtime limits (spec §15).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityLimits {
    pub max_expression_bytes: usize,
    pub max_output_json_bytes: usize,
    pub max_list_len: usize,
    pub max_string_bytes: usize,
    /// Per-step CPU budget for CEL evaluation.
    ///
    /// `cel` 0.13 exposes no step/cost/fuel API for `Program::execute` (only parse recursion
    /// limits), so this value is not enforced as a true per-step counter. CPU-DoS from
    /// comprehensions (`.map`/`.filter`/`.exists`) over large inputs — whose iteration counts are
    /// bounded by input list sizes — is instead mitigated at the evaluation boundary by an
    /// input-size cap (see `evaluate_cel_expression` / `evaluate_cel_expression_with_input`, which
    /// reject root bindings whose serialized JSON exceeds `max_output_json_bytes`) plus the
    /// existing list/string `BudgetGuard` in the stdlib. A real per-step budget keyed on this field
    /// awaits upstream `cel` support.
    pub max_eval_steps: u64,
}

impl Default for SecurityLimits {
    fn default() -> Self {
        Self {
            max_expression_bytes: 256 * 1024,
            max_output_json_bytes: 16 * 1024 * 1024,
            max_list_len: 100_000,
            max_string_bytes: 1024 * 1024,
            max_eval_steps: 1_000_000,
        }
    }
}

impl SecurityLimits {
    // Hard ceilings for caller-supplied limits. These match the secure defaults: callers may only
    // TIGHTEN limits relative to defaults; any attempt to widen beyond a default is capped here.
    // Floors are a functional minimum of 1 so callers cannot zero a limit out (which would either
    // disable a protection or make every evaluation fail).
    const CEIL_EXPRESSION_BYTES: usize = 256 * 1024;
    const CEIL_OUTPUT_JSON_BYTES: usize = 16 * 1024 * 1024;
    const CEIL_LIST_LEN: usize = 100_000;
    const CEIL_STRING_BYTES: usize = 1024 * 1024;
    const CEIL_EVAL_STEPS: u64 = 1_000_000;
    /// Functional floor: every limit must be at least 1.
    const FLOOR: usize = 1;

    /// Return a copy with every field clamped into a safe `[floor, ceiling]` range.
    ///
    /// This is the trust boundary for caller-supplied `SecurityLimits` (e.g. from the WASM editor):
    /// a malicious caller cannot WIDEN a limit beyond its secure default (defeating DoS
    /// protections) nor zero one out below the functional floor of 1. Each field is clamped with
    /// `value.clamp(floor, ceiling)` where the ceiling equals the corresponding [`Default`] value.
    pub fn clamped(self) -> SecurityLimits {
        SecurityLimits {
            max_expression_bytes: self
                .max_expression_bytes
                .clamp(Self::FLOOR, Self::CEIL_EXPRESSION_BYTES),
            max_output_json_bytes: self
                .max_output_json_bytes
                .clamp(Self::FLOOR, Self::CEIL_OUTPUT_JSON_BYTES),
            max_list_len: self.max_list_len.clamp(Self::FLOOR, Self::CEIL_LIST_LEN),
            max_string_bytes: self
                .max_string_bytes
                .clamp(Self::FLOOR, Self::CEIL_STRING_BYTES),
            max_eval_steps: self
                .max_eval_steps
                .clamp(Self::FLOOR as u64, Self::CEIL_EVAL_STEPS),
        }
    }

    pub fn check_expr(&self, src: &str) -> Result<(), String> {
        if src.len() > self.max_expression_bytes {
            return Err(format!(
                "expression exceeds max {} bytes",
                self.max_expression_bytes
            ));
        }
        Ok(())
    }

    /// Serialized JSON size of `records` (approximate output bound, spec §15).
    pub fn check_output_records(
        &self,
        records: &std::collections::BTreeMap<String, Vec<serde_json::Value>>,
    ) -> Result<(), String> {
        let bytes = serde_json::to_string(records)
            .map(|s| s.len())
            .map_err(|e| e.to_string())?;
        if bytes > self.max_output_json_bytes {
            return Err(format!(
                "mapping output exceeds max {} bytes (serialized records are {} bytes)",
                self.max_output_json_bytes, bytes
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SecurityLimits;

    #[test]
    fn clamped_caps_overwide_values_to_ceilings_and_raises_zero_to_floor() {
        let defaults = SecurityLimits::default();
        let over_wide = SecurityLimits {
            // Widening attempts (e.g. via a malicious WASM caller) must be capped at the defaults.
            max_expression_bytes: usize::MAX,
            max_output_json_bytes: usize::MAX,
            max_list_len: usize::MAX,
            max_string_bytes: usize::MAX,
            max_eval_steps: u64::MAX,
        };
        let clamped = over_wide.clamped();
        assert_eq!(clamped.max_expression_bytes, defaults.max_expression_bytes);
        assert_eq!(
            clamped.max_output_json_bytes,
            defaults.max_output_json_bytes
        );
        assert_eq!(clamped.max_list_len, defaults.max_list_len);
        assert_eq!(clamped.max_string_bytes, defaults.max_string_bytes);
        assert_eq!(clamped.max_eval_steps, defaults.max_eval_steps);

        // Zeros must be raised to the functional floor of 1, never left at 0.
        let zeroed = SecurityLimits {
            max_expression_bytes: 0,
            max_output_json_bytes: 0,
            max_list_len: 0,
            max_string_bytes: 0,
            max_eval_steps: 0,
        };
        let clamped = zeroed.clamped();
        assert_eq!(clamped.max_expression_bytes, 1);
        assert_eq!(clamped.max_output_json_bytes, 1);
        assert_eq!(clamped.max_list_len, 1);
        assert_eq!(clamped.max_string_bytes, 1);
        assert_eq!(clamped.max_eval_steps, 1);
    }

    #[test]
    fn clamped_preserves_tightened_values() {
        // Callers may TIGHTEN below defaults; those values pass through unchanged.
        let tightened = SecurityLimits {
            max_expression_bytes: 10,
            max_output_json_bytes: 20,
            max_list_len: 30,
            max_string_bytes: 40,
            max_eval_steps: 50,
        };
        let clamped = tightened.clamped();
        assert_eq!(clamped.max_expression_bytes, 10);
        assert_eq!(clamped.max_output_json_bytes, 20);
        assert_eq!(clamped.max_list_len, 30);
        assert_eq!(clamped.max_string_bytes, 40);
        assert_eq!(clamped.max_eval_steps, 50);
    }
}
