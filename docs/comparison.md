# QuerySense vs Alternatives

Honest comparison of PostgreSQL EXPLAIN analyzers. We believe in transparency.

## Feature Comparison

| Feature | QuerySense | pgMustard | pganalyze | PEV2 |
|---------|-----------|-----------|-----------|------|
| **Price** | Free | $19/mo | $99+/mo | Free |
| **CLI-first** | Yes | No | No | No |
| **Works offline** | Yes | No | No | Yes |
| **PostgreSQL** | Yes | Yes | Yes | Yes |
| **Open source** | Yes (MIT) | No | No | Yes |
| **Self-hosted** | Yes | No | $$$$ | Yes |
| **Rule count** | 11 | ~20 | 50+ | N/A (visualization) |
| **AI explanations** | Optional | Built-in | Built-in | No |
| **CI/CD integration** | Planned | No | Yes | No |
| **Continuous monitoring** | Planned | No | Yes | No |

## When to Use Each Tool

### Choose QuerySense if you:

- Want a **free, open-source** solution
- Need to work **offline** (no data leaves your machine)
- Want **CLI-first** workflow for scripts and automation
- Prefer **copy-paste SQL fixes** over dashboards
- Value **speed** (650+ plans/second)
- Have security requirements (no cloud dependencies)

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

## Performance Benchmarks

Tested on M1 MacBook Pro, 16GB RAM:

| Tool | Plans/Second | Memory (250k plans) |
|------|--------------|---------------------|
| QuerySense | 652 | 1.7GB |
| PEV2 | ~100 | N/A (web-based) |
| pgMustard | N/A | Cloud-based |
| pganalyze | N/A | Cloud-based |

QuerySense is the fastest local EXPLAIN analyzer available.

## What We Don't Do (Yet)

Be honest about limitations:

| Feature | Status |
|---------|--------|
| Cloud dashboard | Not planned |
| Continuous monitoring | v0.5.0 roadmap |
| Slack/PagerDuty alerts | v0.5.0 roadmap |
| Historical comparisons | v0.4.0 roadmap |
| Multi-query batch analysis | v0.4.0 roadmap |
| Team/enterprise features | Not planned (stay simple) |

## Our Philosophy

QuerySense is built for **individual developers and small teams** who:

1. Want to fix slow queries **right now**
2. Don't need a dashboard
3. Value **speed and simplicity**
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
| Pretty visualizations | **PEV2** |
| AI explanations | **pgMustard** ($19/mo) |
| Production monitoring | **pganalyze** ($99+/mo) |

---

*Last updated: February 2026*

*Have feedback? Open an issue on [GitHub](https://github.com/JosephAhn23/Query-Sense/issues).*
