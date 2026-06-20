//! Per-evaluation thread-local context (ctx.* for host functions, warnings).
//!
//! # Thread-local usage contract
//!
//! The evaluation context (`CTX`) and warnings (`WARNINGS`) are stored in
//! `thread_local!` storage.  Callers **must** obey all of the following rules:
//!
//! 1. **Single-threaded evaluation only.**  Call [`set_eval_ctx`] on the same
//!    OS thread that will drive the CEL evaluation, then call [`clear_eval_ctx`]
//!    (or [`take_warnings`] / [`clear_warnings`]) on that same thread when the
//!    evaluation is complete.
//!
//! 2. **No `.await` across the context window.**  If this module is used from
//!    an async runtime (e.g. Tokio), the context MUST be set, used, and cleared
//!    entirely within a single synchronous, non-yield section of code.  Do NOT
//!    hold the context across an `.await` point: async tasks can be moved to a
//!    different worker thread when they resume, which means the thread-local
//!    will either be missing (the new thread has never set it) or will belong
//!    to a completely different concurrent task.
//!
//! 3. **No cross-task sharing.**  Thread-locals are per-thread, not per-task.
//!    Two async tasks running on the same OS thread share the same thread-local
//!    slot, so concurrent evaluations on the same thread would observe and
//!    clobber each other's context.  Serialise evaluations or use separate
//!    threads if you need concurrency.

use std::cell::RefCell;

thread_local! {
    static CTX: RefCell<Option<FunctionRequestContext>> = const { RefCell::new(None) };
    static WARNINGS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone, Debug, Default)]
pub struct FunctionRequestContext {
    pub country: Option<String>,
    pub timezone: Option<String>,
    pub today: Option<String>,
}

impl FunctionRequestContext {
    pub fn from_json(ctx: &serde_json::Value) -> Self {
        Self {
            country: ctx
                .get("country")
                .and_then(|value| value.as_str())
                .map(ToString::to_string),
            timezone: ctx
                .get("timezone")
                .and_then(|value| value.as_str())
                .map(ToString::to_string),
            today: ctx
                .get("today")
                .and_then(|value| value.as_str())
                .map(ToString::to_string),
        }
    }
}

/// Store the per-evaluation request context in thread-local storage.
///
/// **Usage contract:** this MUST be called on the same OS thread that will
/// perform the CEL evaluation, and the context MUST be cleared (via
/// [`clear_eval_ctx`]) before that thread is returned to an async executor or
/// thread pool.  Never hold the context across an `.await` point — see the
/// [module-level documentation](self) for the full contract.
pub fn set_eval_ctx(ctx: FunctionRequestContext) {
    CTX.with(|c| *c.borrow_mut() = Some(ctx));
}

/// Remove the per-evaluation request context from thread-local storage.
///
/// Must be called on the same OS thread that called [`set_eval_ctx`], after
/// the CEL evaluation completes and before yielding back to an async executor.
/// See the [module-level documentation](self) for the full usage contract.
pub fn clear_eval_ctx() {
    CTX.with(|c| *c.borrow_mut() = None);
}

pub fn eval_ctx_get(path: &[&str]) -> Option<serde_json::Value> {
    CTX.with(|c| {
        let ctx = c.borrow();
        let ctx = ctx.as_ref()?;
        match path {
            ["country"] => ctx.country.clone().map(serde_json::Value::String),
            ["timezone"] => ctx.timezone.clone().map(serde_json::Value::String),
            ["today"] => ctx.today.clone().map(serde_json::Value::String),
            _ => None,
        }
    })
}

pub fn take_warnings() -> Vec<String> {
    WARNINGS.with(|w| {
        let mut v = w.borrow_mut();
        std::mem::take(&mut *v)
    })
}

pub fn clear_warnings() {
    WARNINGS.with(|w| w.borrow_mut().clear());
}

pub fn push_warning(msg: String) {
    WARNINGS.with(|w| w.borrow_mut().push(msg));
}
