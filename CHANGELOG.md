# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

## [0.2.0] - 2026-06-20

### Added
- Documented and regression-tested support for CEL collection (comprehension)
  macros: `filter`, `map`, `exists`, `exists_one`, and `all`, alongside
  `size()` and list indexing. These are provided by the underlying `cel` crate
  and are available in every mapping expression; the new tests lock the
  behaviour in so downstream consumers can depend on it.

### Security
- Hardened untrusted-input handling across standalone CEL evaluation, compiled
  CEL evaluation, preview, v0.1 mappings, PublicSchema formulas, Python limits,
  and WebAssembly limits.
- Capped PublicSchema target array indexes during compilation and guarded
  runtime writes to avoid unbounded array padding.
- Replaced reachable date-helper panics with structured overflow errors.
- Added budget checks for regex helper patterns, recursive list flattening, and
  generated text size.
- Clamped caller-provided security limits in Python and WebAssembly bindings.

### Changed
- Bumped all Rust workspace crates and the Python package metadata to `0.2.0`.

### Notes
- CEL collection macros already evaluated before this release. `0.2.0` makes
  that support explicit with tests and docs, and includes the security
  hardening merged after `crosswalk-core-v0.1.1`.
