# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Thread-safe analyzer using `contextvars` (fixes race condition in concurrent usage)
- Async support via `analyze_async()` method for web servers and async applications
- Built-in LRU caching with `cache_enabled=True` option
- Structured observability with `AnalyzerMetrics` and `Tracer` classes
- `SQLEnhanceable` protocol for rules to provide SQL-enhanced recommendations
- `get_current_query_info()` function for thread-safe access to query context
- `SECURITY.md` with vulnerability reporting process
- `STABILITY.md` with stability guarantees
- `CHANGELOG.md` following Keep a Changelog format
- `py.typed` marker for PEP 561 compliance
- Backwards compatibility tests

### Changed
- `Analyzer` now uses `contextvars` instead of instance variables for thread safety
- SQL enhancement logic moved from hardcoded rule IDs to `SQLEnhanceable` protocol
- `SeqScanLargeTable` rule now implements `SQLEnhanceable` protocol (version 2.1.0)
- Updated dependency version bounds for stability

### Fixed
- **CRITICAL**: Thread-safety bug where `_current_query_info` was stored on instance
- Race condition when using same `Analyzer` instance across multiple threads

### Deprecated
- None

### Removed
- None

### Security
- Added `SECURITY.md` with vulnerability reporting process
- Thread-safety fix prevents potential data leakage in concurrent environments

---

## [0.3.1] - 2026-02-06

### Fixed
- Documentation improvements
- Minor bug fixes

---

## [0.3.0] - 2026-01-15

### Added
- Initial PyPI release
- PostgreSQL EXPLAIN JSON parser with resource limits
- Rule-based analyzer with 11 built-in detection rules
- CLI with `analyze`, `fix`, and `rules` commands
- Optional Claude AI explainer integration
- Index recommendation engine with cost estimation
- SQL query parsing for enhanced recommendations
- Plan fingerprinting for caching support
- Before/after comparison utilities

### Rules Included
- `SEQ_SCAN_LARGE_TABLE` - Sequential scans on large tables
- `BAD_ROW_ESTIMATE` - Severe planner estimation errors
- `NESTED_LOOP_LARGE_TABLE` - O(n*m) nested loop problems
- `SPILLING_TO_DISK` - Hash/sort operations spilling to disk
- `MISSING_BUFFERS` - Missing BUFFERS option in EXPLAIN
- `FOREIGN_KEY_INDEX` - Foreign keys without indexes
- `STALE_STATISTICS` - Outdated table statistics
- `TABLE_BLOAT` - Table bloat issues
- `CORRELATED_SUBQUERY` - Correlated subqueries
- `EXCESSIVE_SEQ_SCANS` - Multiple sequential scans
- `PARALLEL_QUERY_NOT_USED` - Parallel query opportunities

---

## Migration Guide

### Upgrading to 0.4.0

#### Thread Safety Changes

The analyzer is now thread-safe. If you were using workarounds for the thread-safety issue, you can remove them:

```python
# Before (workaround)
def analyze_query(query):
    analyzer = Analyzer()  # Create new instance per call
    return analyzer.analyze(query)

# After (0.4.0+)
analyzer = Analyzer()  # Safe to share across threads
def analyze_query(query):
    return analyzer.analyze(query)  # Thread-safe
```

#### New Caching Feature

Enable caching for repeated analysis:

```python
# New in 0.4.0
analyzer = Analyzer(
    cache_enabled=True,
    cache_size=100,
    cache_ttl=300.0,
)
```

#### Async Support

For async applications:

```python
# New in 0.4.0
result = await analyzer.analyze_async(explain, sql)
```

#### Custom Rules with SQL Enhancement

If you have custom rules that need SQL-based enhancement:

```python
from querysense.analyzer.rules.base import Rule, SQLEnhanceable

class MyRule(Rule, SQLEnhanceable):
    def enhance_with_sql(self, finding, query_info):
        # Provide better suggestions when SQL is available
        return finding.model_copy(update={"suggestion": "..."})
```

---

## Version History

| Version | Release Date | Python | Status |
|---------|--------------|--------|--------|
| 0.4.0   | Unreleased   | 3.11+  | Development |
| 0.3.1   | 2026-02-06   | 3.11+  | Current |
| 0.3.0   | 2026-01-15   | 3.11+  | Supported |

[Unreleased]: https://github.com/JosephAhn23/Query-Sense/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/JosephAhn23/Query-Sense/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/JosephAhn23/Query-Sense/releases/tag/v0.3.0
