# QuerySense

**AI-powered PostgreSQL query performance analyzer**

QuerySense analyzes your PostgreSQL `EXPLAIN ANALYZE` output and identifies performance issues with actionable recommendations. It combines deterministic heuristic rules with LLM-powered explanations to help you understand and fix slow queries.

## Features

- 🔍 **Detects common performance issues:**
  - Sequential scans on large tables
  - Missing indexes
  - Poor row estimates (bad statistics)
  - Expensive sorts spilling to disk
  - Nested loops with high iteration counts
  
- 🤖 **AI-powered explanations** that tell you *why* something is slow and *how* to fix it

- 📊 **Works with real EXPLAIN output** - no database connection required for basic analysis

- 🛡️ **Production-grade code** with comprehensive error handling and type safety

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/querysense.git
cd querysense

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with development dependencies
pip install -e ".[dev]"
```

### Generate EXPLAIN Output

Run your slow query with `EXPLAIN (ANALYZE, FORMAT JSON)`:

```sql
-- In psql or your SQL client
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT o.*, u.email
FROM orders o
JOIN users u ON o.user_id = u.id
WHERE o.status = 'pending'
ORDER BY o.created_at DESC
LIMIT 100;
```

Save the output to a file (e.g., `explain.json`).

### Analyze

```bash
querysense analyze explain.json
```

## Usage

### CLI Commands

```bash
# Analyze an EXPLAIN file
querysense analyze explain.json

# Allow plain EXPLAIN (without ANALYZE data)
querysense analyze explain.json --allow-plain

# Output as JSON (for programmatic use)
querysense analyze explain.json --json

# Show version
querysense --version
```

### Programmatic Usage

```python
from querysense.parser import parse_explain

# Parse from file
output = parse_explain("explain.json")

# Parse from string
output = parse_explain('{"Plan": {...}}')

# Iterate through all nodes
for node in output.all_nodes:
    if node.node_type == "Seq Scan" and (node.actual_rows or 0) > 10000:
        print(f"Large sequential scan on {node.relation_name}")

# Find slow nodes
slow_nodes = output.find_slow_nodes(threshold_ms=100)
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=querysense

# Run specific test file
pytest tests/test_parser.py -v
```

### Type Checking

```bash
# Run mypy
mypy src/querysense
```

### Linting

```bash
# Run ruff
ruff check src tests

# Auto-fix issues
ruff check --fix src tests
```

## Architecture

```
querysense/
├── parser/          # EXPLAIN JSON parsing and validation
│   ├── models.py    # Pydantic models for plan nodes
│   └── parser.py    # Parsing logic and error handling
├── analyzer/        # Heuristic rules engine
│   └── rules/       # Individual detection rules
├── explainer/       # LLM integration for explanations
├── cli/             # Command-line interface
└── output/          # Result formatting
```

### Design Principles

1. **Deterministic first:** Core analysis uses heuristic rules that are testable and reliable
2. **LLM for UX:** AI explanations enhance but don't replace deterministic findings
3. **Fail loudly:** Clear error messages over silent failures
4. **Type safety:** Full type coverage with Pydantic and mypy strict mode

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | API key for Claude explanations | Required for AI explanations |
| `QUERYSENSE_MODEL` | Claude model to use | `claude-3-haiku-20240307` |
| `QUERYSENSE_TIMEOUT` | API request timeout (seconds) | `30` |
| `DATABASE_URL` | PostgreSQL connection for schema introspection | Optional |

## Roadmap

- [x] EXPLAIN JSON parser with full type coverage
- [ ] Core analyzer rules (sequential scan, missing index, etc.)
- [ ] LLM explanation integration
- [ ] CLI with rich output
- [ ] Web API
- [ ] Query plan visualization
- [ ] Schema introspection

## License

MIT

## Contributing

Contributions welcome! Please read the contributing guidelines and ensure tests pass before submitting PRs.

