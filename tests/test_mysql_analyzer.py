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
