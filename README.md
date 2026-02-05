# QuerySense

Find missing indexes in PostgreSQL EXPLAIN plans.

## What It Does

Analyzes PostgreSQL `EXPLAIN` output and suggests concrete fixes for performance issues.
```bash
$ python -m querysense.cli.main analyze plan.json

Found 1 issue(s):

[WARNING] Sequential scan on orders (487,293 rows)
   Sequential scan read 487,293 rows from table 'orders'. Filter applied: 
   (status = 'pending'::text) Filter removed 12,707 rows, keeping only 487,293.
   
   Fix:
   CREATE INDEX idx_orders_status ON orders(status);
   -- Docs: https://www.postgresql.org/docs/current/indexes-types.html
```

## Install
```bash
git clone https://github.com/JosephAhn23/QuerySense.git
cd QuerySense
pip install -e .
```

## Usage

### 1. Get EXPLAIN output from PostgreSQL
```bash
psql -c "EXPLAIN (ANALYZE, FORMAT JSON) 
  SELECT * FROM orders WHERE status = 'pending'" > plan.json
```

### 2. Analyze it
```bash
python -m querysense.cli.main analyze plan.json
```

### 3. Apply the suggested fix
```sql
CREATE INDEX idx_orders_status ON orders(status);
```

## Output Formats

**Human-readable (default):**
```bash
querysense analyze plan.json
```

**JSON (for scripting):**
```bash
querysense analyze plan.json --json
```

## What It Detects

Currently detects:
- Sequential scans on large tables (>10k rows)
- Row estimation errors (planner vs actual)

Coming soon based on user feedback:
- Nested loops without indexes
- Sorts on large datasets
- Hash joins with memory spills

## Examples

**Well-optimized query:**
```bash
$ querysense analyze good_plan.json
+--------------------------------- QuerySense ---------------------------------+
| No performance issues found!                                                 |
+------------------------------------------------------------------------------+
```

**Multiple issues:**
```bash
$ querysense analyze bad_plan.json

Found 2 issue(s):

[WARNING] Sequential scan on users (1,047,293 rows)
   Fix: CREATE INDEX idx_users_email ON users(email);

[INFO] Row estimation error on orders
   Planner estimated 100 rows, actually scanned 487,293 (4,873x off)
   Fix: ANALYZE orders;
```

## Testing
```bash
pytest  # 66 tests pass
```

## Status

**Early alpha.** Works on real EXPLAIN plans, but only catches sequential scan issues right now.

This is intentionally minimal - adding rules based on actual user needs, not speculation.

## Contributing

Have a slow query? Share the EXPLAIN plan:
```bash
psql -c "EXPLAIN (ANALYZE, FORMAT JSON) YOUR_SLOW_QUERY" > slow.json
```

Open an issue with `slow.json` attached. If it's a common pattern, we'll add a rule.

### Adding a Rule

Rules are ~20 lines. Here's the template:
```python
# querysense/analyzer/rules/your_rule.py
from querysense.analyzer.rules.base import Rule
from querysense.analyzer.models import Finding, Severity

class YourRule(Rule):
    """Detects [specific problem]."""
    
    def analyze(self, node, context):
        if node.node_type == "Something Bad":
            yield Finding(
                rule_id="YOUR_RULE",
                severity=Severity.WARNING,
                title=f"Problem with {node.relation_name}",
                description="Why this is slow...",
                suggestion="CREATE INDEX ...",
                context=context
            )
```

See `querysense/analyzer/rules/` for examples.

## Why This Exists

Reading EXPLAIN plans is hard. This tool:
- Parses the JSON for you
- Highlights actual problems (not noise)
- Suggests copy-paste fixes
- Links to PostgreSQL docs

No API keys, no telemetry, no LLM - just deterministic rules that work offline.

## Non-Goals

- **Not a query optimizer** - Doesn't rewrite your SQL
- **Not a monitoring tool** - Doesn't connect to your database
- **Not AI-powered** - Deterministic rules you can understand and trust

## License

MIT

## Links

- **Issues**: https://github.com/JosephAhn23/QuerySense/issues
- **PostgreSQL EXPLAIN docs**: https://www.postgresql.org/docs/current/using-explain.html
- **Index types**: https://www.postgresql.org/docs/current/indexes-types.html

---

**Built by developers tired of manually reading EXPLAIN plans.**

*v0.1.0 - Ships with 2 rules, 66 tests, zero dependencies.*
