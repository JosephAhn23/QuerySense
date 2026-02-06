# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-02-06

### Added - Design Upgrade (Overkill Rigour)

#### Evidence Level System (Principle: Deterministic Core, Progressive Enhancement)
- `EvidenceLevel` enum: `PLAN`, `PLAN+SQL`, `PLAN+SQL+DB`
- Explicit tracking of what data sources inform findings
- `evidence_level` field on `AnalysisResult`

#### SQL AST Parser with pglast (Principle: Use the Source of Truth)
- New `sql_ast.py` module using pglast (PostgreSQL's actual parser)
- `SQLConfidence` enum: `HIGH` (pglast), `MEDIUM` (sqlparse), `LOW` (failed)
- Falls back to sqlparse when pglast unavailable
- Hard rule: If AST parse fails, disable index advice or mark as heuristic

#### Rule Run Status (Principle: Observable Failure, Not Silent)
- `RuleRunStatus` enum: `PASS`, `SKIP`, `FAIL`
- `RuleRun` model with rule_id, version, status, runtime_ms, error_summary
- `rule_runs` tuple on `AnalysisResult` for explicit observability
- `degraded` flag when analysis ran with some rules skipped/failed

#### Configuration System (Principle: Config is Not Code)
- New `config.py` module following 12-factor principles
- `Config` class with environment variable loading
- Per-rule thresholds via `QUERYSENSE_RULE_<RULE_ID>_<SETTING>`
- Per-table overrides via `QUERYSENSE_TABLE_<TABLE>_<SETTING>`
- Environment profiles: development/staging/production

#### Impact Bands (Principle: Never Overclaim)
- `ImpactBand` enum: `LOW`, `MEDIUM`, `HIGH`, `UNKNOWN`
- `assumptions` field on `Finding` for explicit assumptions
- `verification_steps` field for actionable verification
- Replaces specific multiplier claims ("57x faster")

#### Database Probe for Level 3 Analysis
- New `db/` module with `DBProbe` protocol
- `AsyncpgProbe` implementation for PostgreSQL
- `list_indexes(table)`: Check if suggested indexes exist
- `table_stats(table)`: Get statistics freshness, row counts
- `settings()`: Get relevant PostgreSQL settings
- `query_stats(queryid)`: Query pg_stat_statements (optional)

#### Rule Dependency DAG
- `requires` and `provides` fields on `Rule` class
- Topological sort of rules based on dependencies
- Rules SKIP if prerequisites not met
- Built-in capabilities: `sql_ast`, `sql_ast_high`, `db_probe`

#### Output Module (Principle: Presentation ≠ Domain Logic)
- New `output/` module separating rendering from analysis
- `render_text()`: Rich terminal output for CLI
- `render_json()`: Stable JSON schema for API
- `render_markdown()`: GitHub/Slack-friendly format
- `AnalysisResultSchema` for OpenAPI integration

#### Plan Compare Mode (Principle: Track Change)
- Enhanced `comparator.py` with node-level diffs
- `NodeDiff` class tracking scan type changes, row/loop/buffer changes
- `PlanComparison` class with cost_reduction_percent, time_reduction_percent
- `compare_plans()` function for before/after plan comparison

#### Reproducibility Info
- `ReproducibilityInfo` model with hashes for bug reports
- `analysis_id`, `plan_hash`, `sql_hash`, `config_hash`, `rules_hash`
- Enables reproducible bug reports and cache validation

### Changed
- Version bump to 0.5.0
- `Finding` model now includes `impact_band`, `assumptions`, `verification_steps`
- `AnalysisResult` now includes `evidence_level`, `sql_confidence`, `rule_runs`, `reproducibility`
- `ExecutionMetadata` now includes `rules_skipped`, `analysis_duration_ms`, `cache_hit`
- `Rule` base class now supports `requires` and `provides` for dependency DAG
- `RuleContext` class added for advanced rule execution

### Dependencies
- Added optional `pglast>=6.0` for accurate SQL parsing
- Added optional `psycopg[binary]>=3.1.0` for DB probe

---

## [0.4.0] - 2026-02-06

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
| 0.5.0   | 2026-02-06   | 3.11+  | Current |
| 0.4.0   | 2026-02-06   | 3.11+  | Supported |
| 0.3.1   | 2026-02-06   | 3.11+  | Supported |
| 0.3.0   | 2026-01-15   | 3.11+  | Supported |

[Unreleased]: https://github.com/JosephAhn23/Query-Sense/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/JosephAhn23/Query-Sense/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/JosephAhn23/Query-Sense/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/JosephAhn23/Query-Sense/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/JosephAhn23/Query-Sense/releases/tag/v0.3.0
