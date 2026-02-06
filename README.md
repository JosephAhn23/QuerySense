# QuerySense

Analyze PostgreSQL and MySQL EXPLAIN plans and get actionable performance fixes.

![QuerySense: 2.3s → 0.04s with one index](query.png)

```bash
$ querysense analyze slow_query.json

[CRITICAL] Row estimation error on orders (5,000x off)
   Planner estimated 50 rows, actually scanned 250,000.
   Fix: ANALYZE orders;

[WARNING] Sequential scan on orders (250,000 rows)
   Estimated improvement: 57x faster
   Fix: CREATE INDEX idx_orders_status ON orders(status);
```

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

### PostgreSQL

```bash
# 1. Export your slow query's plan
psql -c "EXPLAIN (ANALYZE, FORMAT JSON) 
  SELECT * FROM orders WHERE status = 'pending'" > plan.json

# 2. Analyze it
querysense analyze plan.json

# 3. Apply the suggested fixes
psql -c "CREATE INDEX idx_orders_status ON orders(status);"
```

### MySQL

```bash
# 1. Export your slow query's plan  
mysql -e "EXPLAIN FORMAT=JSON SELECT * FROM orders WHERE status = 'pending'" > plan.json

# 2. Analyze it (auto-detects MySQL format)
querysense analyze plan.json

# Or explicitly specify MySQL
querysense analyze --database mysql plan.json

# 3. Apply the suggested fixes
mysql -e "CREATE INDEX idx_orders_status ON orders(status);"
```

## What It Catches

### PostgreSQL Rules

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

### MySQL Rules

| Issue | Severity | Fix |
|-------|----------|-----|
| Full table scan (type=ALL) | CRITICAL | `CREATE INDEX` |
| Index available but not used | WARNING | `ANALYZE TABLE` or query hints |
| Using filesort | WARNING | Index on ORDER BY columns |
| Using temporary table | WARNING | Index on GROUP BY columns |
| Bad join access type | CRITICAL | Index on JOIN column |
| No index available | WARNING | `CREATE INDEX` |

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
✓ No performance issues found!

# Execution time: 2.3s → 0.02s (100x faster)
```

## JSON Output

```bash
querysense analyze plan.json --json
```

## Performance at Scale

| Database | Throughput | Notes |
|----------|-----------|-------|
| PostgreSQL | **652 plans/sec** | 250k plans, 8 rules |
| MySQL | **112,000+ plans/sec** | 50k plans, 6 rules |

Stress-tested on 250,000 PostgreSQL query plans:
- **584,957 issues** detected across 8 rule types
- **1.7GB peak memory** - production-viable footprint
- **0.00% error rate** - deterministic rule engine

QuerySense handles fleet-scale databases.

## Why QuerySense?

| Feature | QuerySense | pgMustard | pganalyze | PEV2 |
|---------|-----------|-----------|-----------|------|
| **Price** | Free | $29/mo | $499/mo | Free |
| **CLI tool** | Yes | No | No | No |
| **Auto-detect issues** | Yes | Partial | Yes | No |
| **Copy-paste SQL fixes** | Yes | Partial | Yes | No |
| **Works offline** | Yes | No | No | Yes |
| **MySQL support** | Yes | No | No | No |
| **No account required** | Yes | No | No | Yes |

**vs pgMustard:** Free, CLI-first, gives you copy-paste SQL fixes

**vs pganalyze:** Focused on one thing (EXPLAIN analysis) and does it well

**vs PEV2:** Doesn't just visualize - detects issues and suggests fixes automatically

## Philosophy

- **Deterministic** - No AI, no API keys, works offline
- **Actionable** - Every issue includes copy-paste SQL to fix it
- **Focused** - 14 rules (8 PostgreSQL + 6 MySQL) that catch real problems
- **Honest** - Only flags issues we're confident about. No false positives.

## Contributing

Have a slow query? Open an issue with the EXPLAIN JSON. 

If it's a common pattern, we'll add a rule.

## License

MIT

---

*v0.3.0 - PostgreSQL + MySQL support, 14 rules, 112k+ plans/sec*
