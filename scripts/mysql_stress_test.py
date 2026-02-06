#!/usr/bin/env python3
"""
MySQL Analyzer Stress Test

Generates synthetic MySQL EXPLAIN plans and benchmarks performance.
Target: 500+ plans/second
"""

import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from querysense.analyzers.mysql import MySQLAnalyzer


# Realistic table and column names
TABLES = ["users", "orders", "products", "customers", "transactions", "sessions", "events", "inventory"]
ACCESS_TYPES = ["ALL", "index", "range", "ref", "eq_ref", "const"]
SELECT_TYPES = ["SIMPLE", "PRIMARY", "SUBQUERY", "DERIVED", "UNION"]
EXTRA_OPTIONS = [
    "Using where",
    "Using index",
    "Using filesort",
    "Using temporary",
    "Using temporary; Using filesort",
    "Using index condition",
    "Using where; Using index",
    "",
]


def generate_mysql_plan(problematic: bool = True) -> list[dict]:
    """Generate a synthetic MySQL EXPLAIN row."""
    table = random.choice(TABLES)
    
    if problematic:
        access_type = random.choices(
            ["ALL", "index", "range", "ref"],
            weights=[50, 20, 15, 15],
            k=1
        )[0]
        rows = random.randint(10_000, 500_000)
        extra = random.choice([
            "Using where",
            "Using filesort",
            "Using temporary",
            "Using temporary; Using filesort",
        ])
        possible_keys = None if random.random() > 0.3 else f"idx_{table}_id"
        key = None
    else:
        access_type = random.choice(["ref", "eq_ref", "const"])
        rows = random.randint(1, 100)
        extra = random.choice(["Using index", "Using where; Using index", ""])
        possible_keys = f"idx_{table}_id"
        key = possible_keys
    
    return [{
        "id": 1,
        "select_type": random.choice(SELECT_TYPES),
        "table": table,
        "partitions": None,
        "type": access_type,
        "possible_keys": possible_keys,
        "key": key,
        "key_len": random.randint(4, 767) if key else None,
        "ref": "const" if key else None,
        "rows": rows,
        "filtered": random.uniform(10, 100),
        "Extra": extra,
    }]


def run_benchmark(num_plans: int) -> dict:
    """Run benchmark with given number of plans."""
    print(f"\nGenerating {num_plans:,} MySQL EXPLAIN plans...")
    plans = [generate_mysql_plan(problematic=random.random() > 0.2) for _ in range(num_plans)]
    
    analyzer = MySQLAnalyzer()
    
    print(f"Analyzing {num_plans:,} plans...")
    start = time.perf_counter()
    
    total_findings = 0
    findings_by_rule = {}
    
    for plan in plans:
        parsed = analyzer.parse_plan(plan)
        findings = analyzer.detect_issues(parsed)
        total_findings += len(findings)
        for f in findings:
            findings_by_rule[f.rule_id] = findings_by_rule.get(f.rule_id, 0) + 1
    
    elapsed = time.perf_counter() - start
    plans_per_second = num_plans / elapsed
    
    return {
        "num_plans": num_plans,
        "elapsed_seconds": elapsed,
        "plans_per_second": plans_per_second,
        "total_findings": total_findings,
        "findings_by_rule": findings_by_rule,
    }


def main():
    print("=" * 60)
    print("MySQL Analyzer Stress Test")
    print("=" * 60)
    
    # Warm up
    print("\nWarm up...")
    run_benchmark(100)
    
    # Run benchmarks at different scales
    results = []
    for scale in [1000, 5000, 10000, 50000]:
        result = run_benchmark(scale)
        results.append(result)
        
        print(f"\n  Scale: {scale:,}")
        print(f"  Time: {result['elapsed_seconds']:.2f}s")
        print(f"  Rate: {result['plans_per_second']:,.0f} plans/sec")
        print(f"  Findings: {result['total_findings']:,}")
    
    # Summary
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print("\n{:<12} {:>10} {:>14} {:>10}".format("Scale", "Time (s)", "Plans/sec", "Findings"))
    print("-" * 50)
    for r in results:
        print("{:<12,} {:>10.2f} {:>14,.0f} {:>10,}".format(
            r["num_plans"],
            r["elapsed_seconds"],
            r["plans_per_second"],
            r["total_findings"],
        ))
    
    # Final verdict
    best = max(results, key=lambda x: x["plans_per_second"])
    print(f"\nPeak performance: {best['plans_per_second']:,.0f} plans/second")
    
    if best["plans_per_second"] >= 500:
        print("PASSED: Exceeds 500 plans/second target")
    else:
        print("FAILED: Below 500 plans/second target")
    
    # Rule breakdown
    print("\nFindings by rule (last run):")
    for rule, count in sorted(results[-1]["findings_by_rule"].items(), key=lambda x: -x[1]):
        print(f"  {rule}: {count:,}")


if __name__ == "__main__":
    main()
