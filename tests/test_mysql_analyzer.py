"""
Tests for MySQL EXPLAIN analyzer.
"""

import json
from pathlib import Path

import pytest

from querysense.analyzers.mysql.parser import MySQLParser, MySQLPlanNode
from querysense.analyzers.mysql.analyzer import MySQLAnalyzer
from querysense.analyzers.mysql.rules import (
    FullTableScan,
    MissingIndex,
    UsingFilesort,
    UsingTemporary,
    BadJoinType,
)


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "mysql"


@pytest.fixture
def mysql_plans() -> dict:
    """Load MySQL test fixtures."""
    with open(FIXTURES_DIR / "explain_plans.json") as f:
        return json.load(f)


@pytest.fixture
def parser() -> MySQLParser:
    return MySQLParser()


@pytest.fixture
def analyzer() -> MySQLAnalyzer:
    return MySQLAnalyzer()


class TestMySQLParser:
    """Tests for MySQL EXPLAIN parser."""
    
    def test_parse_traditional_format(self, parser, mysql_plans):
        """Test parsing traditional EXPLAIN output."""
        result = parser.parse(mysql_plans["full_table_scan"])
        
        assert result.format == "traditional"
        assert len(result.nodes) == 1
        
        node = result.nodes[0]
        assert node.table == "orders"
        assert node.access_type == "ALL"
        assert node.rows == 250000
        assert node.is_full_table_scan
    
    def test_parse_possible_keys(self, parser, mysql_plans):
        """Test parsing possible_keys field."""
        result = parser.parse(mysql_plans["missing_index"])
        node = result.nodes[0]
        
        assert node.possible_keys == ["idx_email", "idx_status"]
        assert node.key is None
        assert node.has_unused_index
    
    def test_parse_extra_field(self, parser, mysql_plans):
        """Test parsing Extra field for filesort/temporary."""
        # Filesort
        result = parser.parse(mysql_plans["using_filesort"])
        assert result.nodes[0].is_using_filesort
        
        # Temporary
        result = parser.parse(mysql_plans["using_temporary"])
        assert result.nodes[0].is_using_temporary
        assert result.nodes[0].is_using_filesort  # Also has filesort
    
    def test_parse_good_query(self, parser, mysql_plans):
        """Test that good queries don't trigger issues."""
        result = parser.parse(mysql_plans["good_query"])
        node = result.nodes[0]
        
        assert node.access_type == "ref"
        assert node.key == "idx_email"
        assert not node.is_full_table_scan
        assert not node.has_unused_index
    
    def test_parse_json_format(self, parser, mysql_plans):
        """Test parsing JSON EXPLAIN FORMAT=JSON output."""
        result = parser.parse(mysql_plans["json_full_table_scan"])
        
        assert result.format == "json"
        assert len(result.nodes) == 1
        
        node = result.nodes[0]
        assert node.table == "orders"
        assert node.access_type == "ALL"
        assert node.rows == 250000
        assert node.is_full_table_scan
        assert "Using where" in node.extra
    
    def test_parse_json_with_filesort(self, parser, mysql_plans):
        """Test parsing JSON EXPLAIN with filesort."""
        result = parser.parse(mysql_plans["json_with_filesort"])
        
        assert result.format == "json"
        assert len(result.nodes) == 1
        
        node = result.nodes[0]
        assert node.is_using_filesort
    
    def test_parse_json_nested_loop(self, parser, mysql_plans):
        """Test parsing JSON EXPLAIN with nested loop joins."""
        result = parser.parse(mysql_plans["json_nested_loop_join"])
        
        assert result.format == "json"
        assert len(result.nodes) == 2
        
        # First table - full scan
        assert result.nodes[0].table == "orders"
        assert result.nodes[0].access_type == "ALL"
        
        # Second table - indexed lookup
        assert result.nodes[1].table == "order_items"
        assert result.nodes[1].access_type == "ref"
        assert result.nodes[1].key == "idx_order_id"
    
    def test_parse_json_good_query(self, parser, mysql_plans):
        """Test that good JSON queries parse correctly."""
        result = parser.parse(mysql_plans["json_good_query"])
        node = result.nodes[0]
        
        assert node.access_type == "const"
        assert node.key == "idx_email"
        assert not node.is_full_table_scan
    
    def test_parse_json_with_temporary(self, parser, mysql_plans):
        """Test parsing JSON EXPLAIN with temporary table."""
        result = parser.parse(mysql_plans["json_with_temporary"])
        
        assert len(result.nodes) == 1
        node = result.nodes[0]
        assert node.is_using_temporary


class TestMySQLRules:
    """Tests for MySQL detection rules."""
    
    def test_full_table_scan_rule(self, parser, mysql_plans):
        """Test full table scan detection."""
        result = parser.parse(mysql_plans["full_table_scan"])
        node = result.nodes[0]
        
        rule = FullTableScan(min_rows=10_000)
        assert rule.check(node) is True
        
        # Small table shouldn't trigger
        rule_strict = FullTableScan(min_rows=1_000_000)
        assert rule_strict.check(node) is False
    
    def test_missing_index_rule(self, parser, mysql_plans):
        """Test missing index detection."""
        result = parser.parse(mysql_plans["missing_index"])
        node = result.nodes[0]
        
        rule = MissingIndex()
        assert rule.check(node) is True
    
    def test_filesort_rule(self, parser, mysql_plans):
        """Test filesort detection."""
        result = parser.parse(mysql_plans["using_filesort"])
        node = result.nodes[0]
        
        rule = UsingFilesort(min_rows=1_000)
        assert rule.check(node) is True
    
    def test_temporary_rule(self, parser, mysql_plans):
        """Test temporary table detection."""
        result = parser.parse(mysql_plans["using_temporary"])
        node = result.nodes[0]
        
        rule = UsingTemporary()
        assert rule.check(node) is True


class TestMySQLAnalyzer:
    """Tests for MySQL analyzer."""
    
    def test_detect_full_table_scan(self, analyzer, mysql_plans):
        """Test full table scan detection."""
        parsed = analyzer.parse_plan(mysql_plans["full_table_scan"])
        findings = analyzer.detect_issues(parsed)
        
        assert len(findings) >= 1
        assert any(f.rule_id == "MYSQL_FULL_TABLE_SCAN" for f in findings)
    
    def test_detect_missing_index(self, analyzer, mysql_plans):
        """Test missing index detection."""
        parsed = analyzer.parse_plan(mysql_plans["missing_index"])
        findings = analyzer.detect_issues(parsed)
        
        # Should detect both full scan and missing index
        rule_ids = [f.rule_id for f in findings]
        assert "MYSQL_MISSING_INDEX" in rule_ids
    
    def test_good_query_no_findings(self, analyzer, mysql_plans):
        """Test that good queries produce no findings."""
        parsed = analyzer.parse_plan(mysql_plans["good_query"])
        findings = analyzer.detect_issues(parsed)
        
        assert len(findings) == 0
    
    def test_database_name(self, analyzer):
        """Test database name property."""
        assert analyzer.database_name == "MySQL"
    
    def test_detect_json_full_table_scan(self, analyzer, mysql_plans):
        """Test full table scan detection on JSON format."""
        parsed = analyzer.parse_plan(mysql_plans["json_full_table_scan"])
        findings = analyzer.detect_issues(parsed)
        
        assert len(findings) >= 1
        assert any(f.rule_id == "MYSQL_FULL_TABLE_SCAN" for f in findings)
    
    def test_detect_json_filesort(self, analyzer, mysql_plans):
        """Test filesort detection on JSON format."""
        parsed = analyzer.parse_plan(mysql_plans["json_with_filesort"])
        findings = analyzer.detect_issues(parsed)
        
        rule_ids = [f.rule_id for f in findings]
        assert "MYSQL_USING_FILESORT" in rule_ids
    
    def test_detect_json_temporary(self, analyzer, mysql_plans):
        """Test temporary table detection on JSON format."""
        parsed = analyzer.parse_plan(mysql_plans["json_with_temporary"])
        findings = analyzer.detect_issues(parsed)
        
        rule_ids = [f.rule_id for f in findings]
        assert "MYSQL_USING_TEMPORARY" in rule_ids
    
    def test_good_json_query_no_findings(self, analyzer, mysql_plans):
        """Test that good JSON queries produce no findings."""
        parsed = analyzer.parse_plan(mysql_plans["json_good_query"])
        findings = analyzer.detect_issues(parsed)
        
        assert len(findings) == 0
    
    def test_suggest_fix_returns_string(self, analyzer, mysql_plans):
        """Test that suggest_fix returns a valid string."""
        parsed = analyzer.parse_plan(mysql_plans["full_table_scan"])
        findings = analyzer.detect_issues(parsed)
        
        assert len(findings) > 0
        fix = analyzer.suggest_fix(findings[0])
        assert isinstance(fix, str)
        assert len(fix) > 0


class TestMySQLPerformance:
    """Performance tests for MySQL analyzer."""
    
    def test_stress_performance(self, analyzer):
        """Test that analyzer meets performance targets."""
        import time
        
        # Generate 10,000 test plans
        plans = []
        for i in range(10_000):
            plans.append([{
                "id": 1,
                "select_type": "SIMPLE",
                "table": f"table_{i % 100}",
                "type": "ALL" if i % 3 == 0 else "ref",
                "possible_keys": "idx_test" if i % 5 == 0 else None,
                "key": "idx_test" if i % 2 == 0 else None,
                "rows": 100_000 if i % 3 == 0 else 100,
                "filtered": 10.0,
                "Extra": "Using filesort" if i % 7 == 0 else "Using where",
            }])
        
        start = time.perf_counter()
        total_findings = 0
        
        for plan in plans:
            parsed = analyzer.parse_plan(plan)
            findings = analyzer.detect_issues(parsed)
            total_findings += len(findings)
        
        elapsed = time.perf_counter() - start
        plans_per_sec = len(plans) / elapsed
        
        # Target: 500+ plans/sec
        assert plans_per_sec > 500, f"Too slow: {plans_per_sec:.0f} plans/sec"
        print(f"\nMySQL analyzer: {plans_per_sec:.0f} plans/sec, {total_findings} findings")
