# QuerySense vs Alternatives

Honest comparison of PostgreSQL EXPLAIN analyzers. We believe in transparency.

## Feature Comparison

| Feature | QuerySense | pgMustard | pganalyze | PEV2 | PgAdmin |
|---------|-----------|-----------|-----------|------|---------|
| **Price** | Free | $19/mo | $99+/mo | Free | Free |
| **CLI-first** | Yes | No | No | No | No |
| **Works offline** | Yes | No | No | Yes | Yes |
| **PostgreSQL** | Yes | Yes | Yes | Yes | Yes |
| **Open source** | Yes (MIT) | No | No | Yes | Yes |
| **Self-hosted** | Yes | No | $$$$ | Yes | Yes |
| **Rule count** | 12 (+7 in dev) | ~20 | 50+ | N/A (visual) | N/A (visual) |
| **Copy-paste SQL fixes** | Yes | Partial | Yes | No | No |
| **AI explanations** | Optional | Built-in | Built-in | No | No |
| **CI/CD integration** | Yes | No | Yes | No | No |
| **Continuous monitoring** | Planned | No | Yes | No | No |
| **TimescaleDB/pgvector** | Compatible | Unknown | Yes | Yes | Yes |

## When to Use Each Tool

### Choose QuerySense if you:

- Want a **free, open-source** solution
- Need to work **offline** (no data leaves your machine)
- Want **CLI-first** workflow for scripts and CI/CD automation
- Prefer **copy-paste SQL fixes** over dashboards
- Value **speed** (650+ plans/second — built for CI pipelines)
- Have security requirements (no cloud dependencies)
- Use PostgreSQL-compatible databases (TimescaleDB, YugabyteDB, pgvector, PostGIS)

### Choose pgMustard if you:

- Want a polished **web UI** with visualizations
- Are willing to pay $19/month
- Only use PostgreSQL
- Prefer AI explanations over rule-based detection

### Choose pganalyze if you:

- Need **continuous monitoring** of production databases
- Want **historical tracking** of query performance
- Have budget for enterprise tooling ($99+/month)
- Need team features (SSO, audit logs)
- Want automatic index recommendations from production data

### Choose PEV2 if you:

- Just want to **visualize** query plans (no recommendations)
- Want a free, open-source solution
- Only use PostgreSQL
- Don't need fix suggestions

### Choose PgAdmin if you:

- Already use PgAdmin as your database management tool
- Want **built-in visual EXPLAIN** without installing anything new
- Don't need automated fix suggestions or CLI integration
- Prefer a GUI-first workflow

> **Tip:** PEV2 and PgAdmin are **complementary** to QuerySense — use them to *see* the plan, then pipe the JSON to QuerySense to get *actionable fixes*.

## Database Compatibility

QuerySense analyzes **plan structure**, not database-specific syntax. Any database that produces PostgreSQL-compatible EXPLAIN JSON works out of the box.

| Database | Status | Notes |
|----------|--------|-------|
| PostgreSQL 12+ | Fully supported | Primary target |
| TimescaleDB | Compatible | Hypertable scans analyzed like regular tables |
| YugabyteDB | Compatible | PostgreSQL-compatible EXPLAIN output |
| pgvector | Compatible | Index scans on vector columns detected |
| PostGIS | Compatible | Spatial index recommendations |
| Citus | Compatible | Distributed plan analysis |
| MySQL | Experimental | Basic EXPLAIN JSON (feature branch) |

## Performance Benchmarks

Tested on M1 MacBook Pro, 16GB RAM:

| Tool | Plans/Second | Memory (250k plans) |
|------|--------------|---------------------|
| QuerySense | 652 | 1.7GB |
| PEV2 | ~100 | N/A (web-based) |
| PgAdmin | N/A | GUI-based |
| pgMustard | N/A | Cloud-based |
| pganalyze | N/A | Cloud-based |

QuerySense is the fastest local EXPLAIN analyzer available — designed to run in CI pipelines, not just interactive debugging.

## What We Don't Do (Yet)

Be honest about limitations:

| Feature | Status |
|---------|--------|
| Cloud dashboard | Not planned |
| Continuous monitoring | v0.6.0 roadmap |
| Slack/PagerDuty alerts | v0.6.0 roadmap |
| Historical comparisons | Shipped (v0.5.0 compare mode) |
| Multi-query batch analysis | v0.6.0 roadmap |
| Team/enterprise features | Not planned (stay simple) |

## Our Philosophy

QuerySense is built for **individual developers and small teams** who:

1. Want to fix slow queries **right now**
2. Don't need a dashboard — they need a **CLI that fits into `git hooks` and CI**
3. Value **speed and automation** over pretty charts
4. Prefer **copy-paste fixes** over reports

We will never:

- Require cloud connectivity
- Lock core features behind paywalls
- Add enterprise bloat

## Migration from Other Tools

### From pgMustard

Export your query plan as JSON, run:

```bash
querysense analyze your_plan.json
```

You'll get the same recommendations, for free.

### From pganalyze

pganalyze offers features QuerySense doesn't (continuous monitoring).
For ad-hoc analysis of slow queries, QuerySense is faster and free.

### From PEV2

PEV2 only visualizes. QuerySense gives you **actionable fixes**.

```bash
# Instead of just seeing the plan...
querysense fix slow_query.json > fixes.sql
psql < fixes.sql
# ...you get immediate improvement
```

## The Bottom Line

| If you need... | Use... |
|---------------|--------|
| Quick fix for a slow query | **QuerySense** |
| Free, offline analysis | **QuerySense** |
| CI/CD query gate | **QuerySense** |
| Pretty visualizations | **PEV2** or **PgAdmin** |
| AI explanations | **pgMustard** ($19/mo) |
| Production monitoring | **pganalyze** ($99+/mo) |

---

*Last updated: February 9, 2026 — informed by [r/PostgreSQL community feedback](https://www.reddit.com/r/PostgreSQL/)*

*Have feedback? Open an issue on [GitHub](https://github.com/JosephAhn23/Query-Sense/issues).*
