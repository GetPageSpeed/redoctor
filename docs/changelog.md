---
title: Changelog
description: Version history and release notes for ReDoctor.
---

# Changelog

All notable changes to ReDoctor are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.5] - 2026-08-19

### Fixed

- Detect nested-quantifier vulnerabilities such as `(a+)+` in automatic mode
- Harden parser, custom regex VM, fuzz seeding, and diagnostic error handling
- Enforce recall-validation deadlines in killable child processes
- Fix VM instruction field/factory collisions for characters and backreferences
- Restore Python 3.6 and 3.7 compatibility in typing and source scanning

## [0.1.4] - 2026-01-10

### Added

- **Match Mode Configuration**: New `MatchMode` setting to control false positive behavior
  - `AUTO` (default): Infer exploitability from pattern anchors (`$`, `\Z`)
  - `FULL`: Conservative mode assuming full-string matching
  - `PARTIAL`: Fewer false positives for search-style matching
- **Anchor Detection Helpers**: New AST functions `has_end_anchor()`, `has_start_anchor()`, `is_anchored()`, `requires_continuation()`
- **NGINX Usage Guide**: New documentation page for checking NGINX location regexes
- **Cursor Rules**: Added `.cursor/rules/20-redos-detection.mdc` documenting architecture decisions

### Changed

- **Improved False Positive Handling**: SCC checker now considers pattern anchoring when determining if multi-transitions are exploitable
  - `(a*)*` without anchors → correctly marked as **safe** (can escape early)
  - `^(a*)*$` with anchor → correctly marked as **exponential** (must match to end)
  - `^([^@]+)+@` → correctly marked as **exponential** (continuation required)
- **NFAwLA Precision**: Look-ahead pruning now preserves all transitions; exploitability determined by `_is_multi_trans_exploitable`

### Documentation

- Updated `docs/configuration.md` with Match Mode section
- Updated `docs/how-it-works.md` with NFAwLA architecture and exploitability checks
- Added `docs/nginx-usage.md` for NGINX-specific guidance

---

## [0.1.3] - 2026-01-09

### Changed

- **Verified 1:1 Behavior with Recheck**: Comprehensive verification that detection behavior matches the reference [recheck](https://github.com/MakeNowJust-Labo/recheck) implementation
  - Added test suite mirroring recheck's `AutomatonCheckerSuite.scala` tests
  - Verified all constant, linear, polynomial, and exponential complexity patterns
  - Confirmed no false positives on safe patterns like `^a+$`, `^[a-z]+$`, `^(a|b)+$`
  - Confirmed no false negatives on vulnerable patterns like `^(a+)+$`, `^(a|a)*$`, `^(a|b|ab)*$`

### Added

- **Extended Test Coverage**
  - `test_recheck_compatibility.py` - Tests for must-be-safe and must-be-vulnerable patterns
  - `test_recheck_full_suite.py` - Full test suite matching recheck's complexity classification
  - `test_recheck_automaton_suite.py` - Direct ports from recheck's Scala test suite

### Fixed

- Edge cases in polynomial ambiguity detection with product automaton

---

## [0.1.2] - 2026-01-08

### Fixed

- Improved detection accuracy for nested quantifiers

---

## [0.1.1] - 2026-01-08

### Fixed

- Fixed false positives on simple patterns like `^a+$`

---

## [0.1.0] - 2026-01-09

### 🎉 Initial Release

First public release of ReDoctor!

### Added

- **Hybrid Analysis Engine**
  - Automaton-based static analysis for patterns without backreferences
  - Fuzz-based dynamic analysis for complex patterns
  - Automatic checker selection based on pattern features

- **Comprehensive Detection**
  - Exponential complexity (O(2^n)) detection
  - Polynomial complexity (O(n^k)) detection
  - Attack string generation with prefix/pump/suffix structure
  - Hotspot identification for vulnerable pattern portions

- **Command Line Interface**
  - `redoctor` command for checking patterns
  - Support for regex flags (`-i`, `-m`, `-s`)
  - Verbose and quiet output modes
  - Stdin support for batch processing
  - Configurable timeout

- **Python API**
  - `check()` function for pattern analysis
  - `is_vulnerable()` and `is_safe()` helpers
  - `HybridChecker` class for reuse
  - Full type hints

- **Configuration**
  - `Config` class with extensive options
  - Preset configurations: `default()`, `quick()`, `thorough()`
  - Timeout, iteration limits, and more

- **Source Code Scanning**
  - `scan_file()` for individual files
  - `scan_directory()` for projects
  - AST-based pattern extraction from `re` module calls

- **Diagnostics**
  - `Diagnostics` result object with full details
  - `Status` enum (SAFE, VULNERABLE, UNKNOWN, ERROR)
  - `Complexity` with type and degree
  - `AttackPattern` with build methods
  - JSON serialization via `to_dict()`

- **Documentation**
  - Comprehensive README
  - Full API documentation
  - CLI reference
  - Pattern examples
  - MkDocs site with Material theme

### Supported Python Versions

- Python 3.6
- Python 3.7
- Python 3.8
- Python 3.9
- Python 3.10
- Python 3.11
- Python 3.12
- Python 3.13

### Links

- [PyPI](https://pypi.org/project/redoctor/)
- [GitHub](https://github.com/GetPageSpeed/redoctor)
- [Documentation](https://redoctor.getpagespeed.com)

---

## Roadmap

### Planned for Future Releases

- **v0.2.0**
  - GitHub Actions integration
  - Pre-commit hook support
  - JSON/SARIF output format
  - Improved NFA construction for edge cases

- **v0.3.0**
  - Pattern rewriting suggestions
  - VS Code extension
  - Performance improvements

- **v1.0.0**
  - Stable API
  - Comprehensive test coverage
  - Production-ready guarantees

---

## Release Notes Format

Each release includes:

- **Added** - New features
- **Changed** - Changes in existing functionality
- **Deprecated** - Features to be removed in future releases
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Vulnerability fixes
