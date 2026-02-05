# QuerySense

Find performance problems in PostgreSQL query plans.

```bash
$ querysense analyze slow_query.json

[CRITICAL] Row estimation error on orders (5,000x off)
   Planner estimated 50 rows, actually scanned 250,000.
   Fix: ANALYZE orders;

[WARNING] Sequential scan on orders (250,000 rows)  
   Fix: CREATE INDEX idx_orders_status ON orders(status);
```

## Install

```bash
pip install -e .
```

## Usage

```bash
# 1. Export your slow query's plan
psql -c "EXPLAIN (ANALYZE, FORMAT JSON) SELECT * FROM orders WHERE status = 'pending'" > plan.json

# 2. Analyze it
querysense analyze plan.json

# 3. Apply the suggested fixes
```

## What It Catches

| Issue | Severity | Fix |
|-------|----------|-----|
| Row estimation >1000x off | CRITICAL | `ANALYZE table` |
| Row estimation >100x off | WARNING | `ANALYZE table` |
| Sequential scan >10k rows | WARNING | `CREATE INDEX` |

## JSON Output

```bash
querysense analyze plan.json --json
```

## Philosophy

- **Deterministic** - No AI, no API keys, works offline
- **Actionable** - Every issue includes copy-paste SQL to fix it
- **Minimal** - 3 rules that catch real problems, not 50 that cause noise

## Contributing

Have a slow query? Open an issue with the EXPLAIN JSON. If it's a common pattern, we'll add a rule.

## License

MIT
