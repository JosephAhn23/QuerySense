# MySQL Support Roadmap (v0.3.0)

## Overview

QuerySense v0.3.0 adds MySQL EXPLAIN analysis alongside existing PostgreSQL support. MySQL has different EXPLAIN output format and terminology, but many performance anti-patterns are universal.

## Status

| Component | Status | Notes |
|-----------|--------|-------|
| Parser (traditional) | ✅ Done | Parses tabular EXPLAIN output |
| Parser (JSON) | 🚧 TODO | EXPLAIN FORMAT=JSON parsing |
| Parser (ANALYZE) | 🚧 TODO | MySQL 8.0.18+ EXPLAIN ANALYZE |
| Rule: Full Table Scan | ✅ Done | type='ALL' detection |
| Rule: Missing Index | ✅ Done | possible_keys without key |
| Rule: Filesort | ✅ Done | Using filesort in Extra |
| Rule: Temporary | ✅ Done | Using temporary in Extra |
| Rule: Bad Join | ✅ Done | ALL/index in joins |
| Rule: No Index Used | ✅ Done | No possible_keys available |
| Tests | ✅ Done | 12 MySQL tests + 78 total |
| CLI Integration | ✅ Done | `querysense analyze --database mysql` |
| Stress Test | ✅ Done | **100,000+ plans/sec** (200x target) |

## Phase 1: Parser (Week 1)

- [x] Parse MySQL EXPLAIN output (traditional format)
- [ ] Parse MySQL EXPLAIN FORMAT=JSON output  
- [ ] Extract: type, possible_keys, key, rows, Extra
- [x] Unit tests with real MySQL plans
- [ ] Handle MySQL 5.7 vs 8.0 differences

## Phase 2: Detection Rules (Week 2)

- [x] FULL_TABLE_SCAN: type='ALL' on tables >10k rows
- [x] MISSING_INDEX: key=NULL with possible_keys available
- [x] USING_FILESORT: Extra contains 'Using filesort'
- [x] USING_TEMPORARY: Extra contains 'Using temporary'
- [x] BAD_JOIN_TYPE: type='ALL' in JOIN operations
- [ ] FULL_INDEX_SCAN: type='index' scanning entire index
- [ ] SUBQUERY_DEPENDENT: DEPENDENT SUBQUERY select_type

## Phase 3: Fix Suggestions (Week 3)

- [x] Generate CREATE INDEX statements
- [x] Suggest FORCE INDEX hints
- [x] Recommend ANALYZE TABLE for stale stats
- [ ] Detect covering index opportunities
- [ ] Suggest query rewrites (e.g., STRAIGHT_JOIN)

## Phase 4: Testing & Docs (Week 4)

- [ ] Stress test with 50k MySQL plans
- [ ] Update README with MySQL examples
- [ ] Add MySQL-specific documentation
- [ ] Compare performance: Postgres vs MySQL analysis
- [ ] Integration tests with real MySQL database

## Release Checklist

- [ ] All tests passing
- [ ] Documentation updated
- [ ] Version bumped to 0.3.0
- [ ] Changelog written
- [ ] PyPI release
- [ ] Announcement post

## MySQL vs PostgreSQL Terminology

| PostgreSQL | MySQL | Description |
|------------|-------|-------------|
| Seq Scan | type='ALL' | Full table scan |
| Index Scan | type='ref' | Index lookup |
| Index Only Scan | type='index' (with Using index) | Covering index |
| Nested Loop | (implicit) | Join strategy |
| Sort | Using filesort | Sort operation |
| HashAggregate | Using temporary | Group/distinct |
| actual_rows | (not available) | Real row count |
| Buffers | (not available) | I/O statistics |

## Key Differences

1. **No ANALYZE equivalent**: MySQL's EXPLAIN doesn't show actual execution times by default. EXPLAIN ANALYZE (8.0.18+) is required.

2. **Access types**: MySQL uses 'type' field with values like ALL, index, range, ref, eq_ref, const instead of node types.

3. **Extra field**: Many MySQL-specific details are in the 'Extra' field (filesort, temporary, index condition, etc.)

4. **No buffer stats**: MySQL doesn't show shared_buffers hits/reads like PostgreSQL.

## Architecture

```
src/querysense/
├── analyzer/           # PostgreSQL analyzer (existing)
│   ├── analyzer.py
│   └── rules/
└── analyzers/          # Multi-database support (new)
    ├── base.py         # BaseAnalyzer interface
    └── mysql/
        ├── parser.py   # MySQL EXPLAIN parser
        ├── analyzer.py # MySQL analyzer
        └── rules.py    # MySQL-specific rules
```
