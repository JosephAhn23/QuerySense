# QuerySense

Analyze PostgreSQL EXPLAIN plans and get actionable performance fixes.

![QuerySense: 2.3s → 0.04s with one index](query.png)

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

**11 rules** that catch real PostgreSQL performance problems.

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

| Feature | QuerySense | pgMustard | pganalyze | PEV2 |
|---------|-----------|-----------|-----------|------|
| **Price** | Free | $29/mo | $499/mo | Free |
| **CLI tool** | Yes | No | No | No |
| **Copy-paste SQL fixes** | Yes | Partial | Yes | No |
| **Works offline** | Yes | No | No | Yes |
| **No account required** | Yes | No | No | Yes |

## Philosophy

- **Deterministic** - No AI, no API keys, works offline
- **Actionable** - Every issue includes copy-paste SQL to fix it
- **Focused** - 11 rules that catch real problems
- **Honest** - Only flags issues we're confident about

## Contributing

Have a slow query? Open an issue with the EXPLAIN JSON. 

If it's a common pattern, we'll add a rule.

## License

MIT

---

*v0.3.0 - 11 PostgreSQL rules, 652 plans/sec*
