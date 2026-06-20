# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

## [0.2.0] - 2026-06-20

### Added
- Documented and regression-tested support for CEL collection (comprehension)
  macros — `filter`, `map`, `exists`, `exists_one`, and `all` — alongside
  `size()` and list indexing. These are provided by the underlying `cel` crate
  and are available in every mapping expression; the new tests lock the
  behaviour in so downstream consumers can depend on it.

### Changed
- Bumped all workspace crates to `0.2.0`.

### Notes
- No runtime behaviour changed in this release: the macros already evaluated
  correctly. The release makes that support explicit (tests + docs) and provides
  a stable version to pin against (e.g. `crosswalk-core = "0.2"`).
