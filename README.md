# QuerySense

[![PyPI version](https://badge.fury.io/py/querysense.svg)](https://badge.fury.io/py/querysense)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Typed](https://img.shields.io/badge/typed-yes-green.svg)](https://www.python.org/dev/peps/pep-0561/)

Analyze PostgreSQL EXPLAIN plans and get actionable performance fixes.

```bash
pip install querysense

## Project Status

| Aspect | Status |
|--------|--------|
| **Version** | 0.5.2 (Beta) |
| **Stability** | [See STABILITY.md](STABILITY.md) |
| **Security** | [See SECURITY.md](SECURITY.md) |
| **Changelog** | [See CHANGELOG.md](CHANGELOG.md) |

> **Note**: QuerySense is in active development (0.x). The API may change between minor versions. Pin to `querysense>=0.5.0,<0.6.0` for stability.

```bash
$ querysense analyze slow_query.json

[CRITICAL] Row estimation error on orders (5,000x off)
   Planner estimated 50 rows, actually scanned 250,000.
   Fix: ANALYZE orders;

[WARNING] Sequential scan on orders (250,000 rows)
   Estimated improvement: 57x faster
   Fix: CREATE INDEX idx_orders_status ON orders(status);

# Get ONLY the SQL fixes (copy-paste ready)
$ querysense fix slow_query.json > fixes.sql
$ psql < fixes.sql
```
![QuerySense: 2.3s → 0.04s with one index](query.png)

## Install

```bash
pip install querysense
```

Or with pipx (recommended for CLI tools):

```bash
pipx install querysense
```

**Optional AI features** (not required for core functionality):

```bash
pip install querysense[ai]  # Adds Claude-based explanations
```

## Usage

```bash
# 1. Export your slow query's plan
psql -c "EXPLAIN (ANALYZE, FORMAT JSON) 
  SELECT * FROM orders WHERE status = 'pending'" > plan.json

# 2. Analyze it
querysense analyze plan.json

# 3. Get copy-paste SQL fixes
querysense fix plan.json > fixes.sql

# 4. Apply the fixes
psql < fixes.sql
```

## What It Catches

| Issue | Severity | Fix |
|-------|----------|-----|
| Row estimation >1000x off | CRITICAL | `ANALYZE table` |
| Row estimation >100x off | WARNING | `ANALYZE table` |
| Sequential scan >10k rows | WARNING | `CREATE INDEX` |
| Nested loop with 1000+ scans | CRITICAL | Add join index |
| Hash/sort spilling to disk | WARNING | Increase `work_mem` |
| Parallel query not used | INFO | Check `max_parallel_workers` |
| Correlated subquery | WARNING | Rewrite as JOIN |
| Missing BUFFERS in EXPLAIN | INFO | Use `EXPLAIN (ANALYZE, BUFFERS)` |
| Foreign key without index | WARNING/CRITICAL | `CREATE INDEX` on FK column |
| Stale statistics | WARNING/CRITICAL | `ANALYZE table` |
| Table bloat | INFO/CRITICAL | `VACUUM ANALYZE` |
| Partition pruning failure | WARNING | Fix partition key in WHERE clause |

**19 rules** that catch real PostgreSQL performance problems — including CTE materialization, lossy bitmap scans, non-sargable filters, plan shape regression, and more.

## Verify It Helped

```bash
# Before
querysense analyze before.json
[WARNING] Sequential scan on orders (250,000 rows)

# Apply fix
psql -c "CREATE INDEX idx_orders_status ON orders(status);"

# After
psql -c "EXPLAIN (ANALYZE, FORMAT JSON) 
  SELECT * FROM orders WHERE status = 'pending'" > after.json
querysense analyze after.json
# No performance issues found!

# Execution time: 2.3s → 0.02s (100x faster)
```

## JSON Output

```bash
querysense analyze plan.json --json
```

## Performance

Stress-tested on 250,000 query plans:
- **652 plans/second** analysis throughput
- **1.7GB peak memory** - production-viable footprint
- **0.00% error rate** - deterministic rule engine

## Why QuerySense?

| Feature | QuerySense | pgMustard | pganalyze | PEV2 | PgAdmin |
|---------|-----------|-----------|-----------|------|---------|
| **Price** | Free | $19/mo | $99+/mo | Free | Free |
| **CLI tool** | Yes | No | No | No | No |
| **Copy-paste SQL fixes** | Yes | Partial | Yes | No | No |
| **Works offline** | Yes | No | No | Yes | Yes |
| **No account required** | Yes | No | No | Yes | Yes |
| **CI/CD ready** | Yes | No | Yes | No | No |

> *Use PEV2 or PgAdmin to **see** the plan. Use QuerySense to **fix** it.*

See [docs/comparison.md](docs/comparison.md) for a detailed breakdown.

## Compatibility

QuerySense works with any database that produces PostgreSQL-compatible EXPLAIN JSON output:

| Database | Status | Notes |
|----------|--------|-------|
| **PostgreSQL** 12+ | Fully supported | Primary target |
| **TimescaleDB** | Compatible | Hypertable scans analyzed like regular tables |
| **YugabyteDB** | Compatible | PostgreSQL-compatible EXPLAIN output |
| **pgvector** | Compatible | Index scans on vector columns detected |
| **PostGIS** | Compatible | Spatial index recommendations supported |
| **Citus** | Compatible | Distributed plan analysis |
| **MySQL** | Experimental | Basic EXPLAIN JSON support ([see branch](https://github.com/JosephAhn23/Query-Sense/tree/feature/mysql-support)) |

> QuerySense analyzes the **plan structure**, not database-specific syntax. If your database outputs PostgreSQL-format EXPLAIN JSON, QuerySense can analyze it.

## Philosophy

- **Deterministic** - No AI, no API keys, works offline
- **Actionable** - Every issue includes copy-paste SQL to fix it
- **Focused** - 19 rules that catch real problems, with more shipping regularly
- **Honest** - Only flags issues we're confident about
- **Fast** - 652 plans/second — built for CI pipelines, not just one-off debugging

## Advanced Usage

### Python API

```python
from querysense import parse_explain, Analyzer

# Parse EXPLAIN JSON
explain = parse_explain("plan.json")

# Analyze with caching (new in 0.4.0)
analyzer = Analyzer(cache_enabled=True)
result = analyzer.analyze(explain)

for finding in result.findings:
    print(f"{finding.severity}: {finding.title}")
    if finding.suggestion:
        print(f"  Fix: {finding.suggestion}")
```

### Async Support (New in 0.4.0)

```python
# For web servers, APIs, async applications
result = await analyzer.analyze_async(explain)
```

### Thread Safety

QuerySense 0.4.0+ is fully thread-safe. You can share a single `Analyzer` instance across multiple threads:

```python
from concurrent.futures import ThreadPoolExecutor

analyzer = Analyzer()  # Safe to share

with ThreadPoolExecutor() as executor:
    results = executor.map(analyzer.analyze, explains)
```

### Observability

```python
# Access built-in metrics
print(f"Cache hit rate: {analyzer.metrics.cache_hit_rate:.1%}")
print(f"Avg duration: {analyzer.metrics.avg_duration_ms:.1f}ms")

# Enable tracing for debugging
analyzer = Analyzer(tracing_enabled=True)
```

## Contributing

Have a slow query? Open an issue with the EXPLAIN JSON. 

If it's a common pattern, we'll add a rule.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## Security

Found a vulnerability? **Do not open a public issue.**

See [SECURITY.md](SECURITY.md) for our security policy and how to report issues.

## License

MIT - See [LICENSE](LICENSE) for details.

---

*v0.5.2 - DAG rule execution, evidence levels, 19 PostgreSQL rules, 652 plans/sec*
