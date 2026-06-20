# Crosswalk

Crosswalk is a deterministic mapping runtime for turning JSON input into JSON
output with YAML mapping documents and CEL expressions. The runtime is written
in Rust, with Python and WebAssembly/TypeScript bindings for application use.

Use Crosswalk when you need:

- A repeatable JSON-to-JSON transform runtime.
- CEL expressions with Crosswalk helper functions for text, dates, IDs, code
  systems, redaction, phone numbers, and JSON utilities; mapping expressions
  also support standard CEL collection macros (`filter`, `map`, `exists`,
  `exists_one`, `all`) on lists — see §7.7 in [`spec.md`](./spec.md).
- Compile-once, evaluate-many mapping workflows.
- The same mapping behavior from Rust, Python, browser, or TypeScript hosts.

## Status

This repository is pre-release and is not published to crates.io, PyPI, or npm
yet. Package names and crate boundaries are close to release shape, but should
be treated as internal until the first external version is cut.

The source repository is:

```text
https://github.com/PublicSchema/crosswalk
```

## Requirements

- Rust 1.83 or newer.
- Python 3.10 through 3.13 for the Python package.
- `wasm-pack`, the `wasm32-unknown-unknown` Rust target, Node.js, and npm for
  the TypeScript/WASM package.
- `uv` is recommended for Python development workflows.

## Quick Start: Rust

Most Rust applications should start with `crosswalk-core`.

```toml
[dependencies]
crosswalk-core = { git = "https://github.com/PublicSchema/crosswalk" }
serde_json = "1"
```

```rust
use crosswalk_core::{EvaluationInput, MappingRuntime, RuntimeOptions};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mapping = r#"
version: "0.1"
name: demo
records:
  people:
    fields:
      name: "source.name"
      country: "default(source.country, ctx.default_country)"
"#;

    let runtime = MappingRuntime::new(RuntimeOptions::default());
    let compiled = runtime.compile_mapping(mapping)?;
    let output = runtime.evaluate(
        &compiled,
        EvaluationInput {
            source: json!({ "name": "Ada" }),
            context: json!({ "default_country": "GB" }),
        },
    );

    assert!(output.errors.is_empty());
    assert_eq!(output.records["people"][0]["name"], json!("Ada"));
    assert_eq!(output.records["people"][0]["country"], json!("GB"));
    Ok(())
}
```

Standalone CEL expressions are available without mapping YAML:

```rust
use crosswalk_core::{EvaluationInput, MappingRuntime, RuntimeOptions};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = MappingRuntime::new(RuntimeOptions::default());
    let value = runtime.evaluate_cel_expression(
        "source.count + 1",
        EvaluationInput {
            source: json!({ "count": 2 }),
            context: json!({}),
        },
    )?;

    assert_eq!(value, json!(3));
    Ok(())
}
```

## Quick Start: Python

The Python package and import name are both `crosswalk`. It is backed by the
Rust `crosswalk-python` crate.

```bash
cd crates/crosswalk-python
uv run --extra dev python -m pytest
```

```python
from crosswalk import MappingRuntime

mapping = """
version: "0.1"
name: demo
records:
  people:
    fields:
      name: "source.name"
"""

runtime = MappingRuntime()
compiled = runtime.compile_mapping(mapping)
output = runtime.evaluate_compiled(compiled, {"name": "Ada"}, {})

assert output["records"]["people"][0]["name"] == "Ada"
```

More examples live in
[`crates/crosswalk-python/examples`](./crates/crosswalk-python/examples).

## Quick Start: TypeScript and WASM

The TypeScript package is `crosswalk-js`. It wraps the generated
`crosswalk-wasm` package with an idiomatic object API.

```bash
cd packages/js
npm ci
npm test
```

```typescript
import { Crosswalk } from "crosswalk-js";

const mapping = `
version: "0.1"
name: demo
records:
  people:
    fields:
      name: "source.name"
`;

const runtime = await Crosswalk.create();
const output = runtime.evaluate(mapping, { name: "Ada" }, {});

console.log(output.records);
```

See [`packages/js/README.md`](./packages/js/README.md) for bundler notes,
low-level WASM access, and more examples.

## Which Package Should I Use?

| Need | Use |
|------|-----|
| Compile and evaluate v0.1 mapping YAML in Rust | [`crosswalk-core`](./crates/crosswalk-core/README.md) |
| Evaluate or preview standalone CEL expressions | [`crosswalk-cel`](./crates/crosswalk-cel/README.md) |
| Call deterministic helpers without CEL | [`crosswalk-functions`](./crates/crosswalk-functions/README.md) |
| Register helper functions into a CEL context | [`crosswalk-functions-cel`](./crates/crosswalk-functions-cel/README.md) |
| Compile and evaluate PublicSchema v0.2 mappings | [`crosswalk-publicschema`](./crates/crosswalk-publicschema/README.md), or the facade in `crosswalk-core` |
| Use Crosswalk from Python | Python package `crosswalk`, implemented by [`crosswalk-python`](./crates/crosswalk-python/README.md) |
| Use Crosswalk from browser or TypeScript | [`crosswalk-js`](./packages/js/README.md), backed by [`crosswalk-wasm`](./crates/crosswalk-wasm/README.md) |

## Repository Layout

| Path | Role |
|------|------|
| [`crates/crosswalk-functions`](./crates/crosswalk-functions/README.md) | Pure deterministic helper functions and code-system registry, with no CEL dependency |
| [`crates/crosswalk-functions-cel`](./crates/crosswalk-functions-cel/README.md) | CEL adapter for helpers, including value conversion, arity, context fallback, warnings, and helper budgets |
| [`crates/crosswalk-cel`](./crates/crosswalk-cel/README.md) | Standalone CEL compile, evaluate, preview, diagnostics, missing-path handling, and security limits |
| [`crates/crosswalk-publicschema`](./crates/crosswalk-publicschema/README.md) | PublicSchema v0.2 property mapping runtime |
| [`crates/crosswalk-core`](./crates/crosswalk-core/README.md) | v0.1 mapping runtime and compatibility facade |
| [`crates/crosswalk-python`](./crates/crosswalk-python/README.md) | PyO3 extension that exposes the Python `crosswalk` module |
| [`crates/crosswalk-wasm`](./crates/crosswalk-wasm/README.md) | Raw `wasm-bindgen` wrapper over `crosswalk-core` |
| [`packages/js`](./packages/js/README.md) | TypeScript wrapper and generated WASM package workflow |

The intended dependency direction and ownership rules are documented in
[`docs/architecture.md`](./docs/architecture.md).

## Development

Rust workspace checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
```

Python checks:

```bash
cd crates/crosswalk-python
uv run --extra dev python -m pytest
uv run --with 'maturin>=1.5,<2' maturin build --release -m Cargo.toml
```

TypeScript and WASM checks:

```bash
cd packages/js
npm ci
npm test
```

Workspace `default-members` include the reusable split crates, `crosswalk-core`,
and `crosswalk-wasm`. The Python crate remains a workspace member, but its
runtime behavior is best verified with pytest after Maturin builds the extension.

## Runtime Notes

Mapping document `errors.mode` (`strict`, `collect`, or `lenient`) wins when it
is set. If a mapping omits it, `RuntimeOptions::default_errors_mode` applies.

Compatibility import paths remain available through `crosswalk_core` during the
crate-split migration. New code should prefer the narrowest crate that owns the
behavior it needs.

## Documentation

| Document | Purpose |
|----------|---------|
| [`docs/architecture.md`](./docs/architecture.md) | Crate ownership, dependency direction, and boundary rules |
| [`docs/extension-guide.md`](./docs/extension-guide.md) | How to add helpers, CEL behavior, PublicSchema behavior, or bindings |
| [`docs/release-checklist.md`](./docs/release-checklist.md) | Pre-release checks for Rust crates, Python wheels, and JS/WASM output |
| [`docs/crate-split-inventory.md`](./docs/crate-split-inventory.md) | Current v0.3 split inventory, preserved pitfalls, and public re-export paths |
| [`spec.md`](./spec.md) | v0.1 mapping behavior and vocabulary |
| [`spec-publicschema-v0.2.md`](./spec-publicschema-v0.2.md) | PublicSchema-native mapping runtime specification |
| [`spec-crate-split-v0.3.md`](./spec-crate-split-v0.3.md) | Crate-boundary split specification |
| [`implementation-plan-publicschema-v0.2.md`](./implementation-plan-publicschema-v0.2.md) | PublicSchema implementation plan |

## License

Licensed under `MIT OR Apache-2.0`. See the workspace
[`Cargo.toml`](./Cargo.toml).
