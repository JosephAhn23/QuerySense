"""
Analyzer - simple rule engine for EXPLAIN plans.

Runs rules against an EXPLAIN output and returns findings.
Designed to work without any external dependencies (no LLM required).

Enhanced with optional SQL parsing for deeper analysis:
- Level 1: EXPLAIN JSON only (default)
- Level 2: EXPLAIN JSON + SQL query (enables specific column recommendations)
- Level 3: EXPLAIN JSON + SQL + DB connection (future)
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any

from querysense.analyzer.errors import RuleError
from querysense.analyzer.models import (
    AnalysisResult,
    ExecutionMetadata,
    Finding,
    RulePhase,
    Severity,
)
from querysense.analyzer.registry import get_registry
from querysense.analyzer.rules.base import Rule
from querysense.analyzer.sql_parser import QueryInfo, SQLQueryAnalyzer

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput

logger = logging.getLogger(__name__)


class Analyzer:
    """
    Simple rule-based query plan analyzer.
    
    Runs rules in two phases:
    1. PER_NODE rules: Analyze individual plan nodes
    2. AGGREGATE rules: Analyze patterns across findings
    
    Example:
        from querysense import parse_explain, Analyzer
        
        explain = parse_explain("plan.json")
        analyzer = Analyzer()
        result = analyzer.analyze(explain)
        
        for finding in result.findings:
            print(f"{finding.severity}: {finding.title}")
            if finding.suggestion:
                print(f"  Fix: {finding.suggestion}")
    """
    
    def __init__(
        self,
        rules: list[Rule] | None = None,
        include_rules: set[str] | None = None,
        exclude_rules: set[str] | None = None,
        fail_fast: bool = False,
        max_findings_per_rule: int = 100,
        parallel: bool = True,
        max_workers: int = 4,
    ) -> None:
        """
        Initialize the analyzer.
        
        Args:
            rules: Custom rules to use (if None, uses registry)
            include_rules: Only run these rule IDs
            exclude_rules: Skip these rule IDs
            fail_fast: Raise on first rule error
            max_findings_per_rule: Limit findings per rule
            parallel: Run rules in parallel
            max_workers: Thread pool size for parallel execution
        """
        if rules is not None:
            self.rules = rules
        else:
            registry = get_registry()
            rule_classes = registry.filter(include=include_rules, exclude=exclude_rules)
            self.rules = [cls() for cls in rule_classes]
        
        self.fail_fast = fail_fast
        self.max_findings_per_rule = max_findings_per_rule
        self.parallel = parallel
        self.max_workers = max_workers
    
    def analyze(
        self,
        explain: "ExplainOutput",
        sql: str | None = None,
    ) -> AnalysisResult:
        """
        Analyze an EXPLAIN output for performance issues.
        
        Args:
            explain: Parsed EXPLAIN output
            sql: Optional SQL query for enhanced analysis.
                 When provided, enables:
                 - Specific column recommendations for indexes
                 - Composite index suggestions
                 - Better join column detection
            
        Returns:
            AnalysisResult with findings and metadata
        """
        start_time = time.perf_counter()
        
        # Parse SQL if provided for enhanced analysis
        query_info: QueryInfo | None = None
        if sql:
            try:
                analyzer = SQLQueryAnalyzer()
                query_info = analyzer.analyze(sql)
                logger.debug(
                    "SQL parsed: %d tables, %d filter cols, %d join cols",
                    len(query_info.tables),
                    len(query_info.filter_columns),
                    len(query_info.join_columns),
                )
            except Exception as e:
                logger.warning("Failed to parse SQL query: %s", e)
        
        # Store query_info for rules to access (via thread-local or context)
        self._current_query_info = query_info
        
        # Split rules by phase
        per_node_rules = [r for r in self.rules if r.phase == RulePhase.PER_NODE]
        aggregate_rules = [r for r in self.rules if r.phase == RulePhase.AGGREGATE]
        
        # Phase 1: PER_NODE rules
        if self.parallel and len(per_node_rules) > 1:
            phase1_findings, phase1_errors = self._run_rules_parallel(
                per_node_rules, explain, prior_findings=[]
            )
        else:
            phase1_findings, phase1_errors = self._run_rules_sequential(
                per_node_rules, explain, prior_findings=[]
            )
        
        # Phase 2: AGGREGATE rules (see phase 1 findings)
        phase2_findings, phase2_errors = self._run_rules_sequential(
            aggregate_rules, explain, prior_findings=phase1_findings
        )
        
        # Combine results
        all_findings = phase1_findings + phase2_findings
        all_errors = phase1_errors + phase2_errors
        
        # Enhance findings with SQL-based recommendations if available
        if query_info:
            all_findings = self._enhance_findings_with_sql(all_findings, query_info)
        
        # Build result
        duration_ms = (time.perf_counter() - start_time) * 1000
        
        return AnalysisResult(
            findings=tuple(sorted(all_findings, key=lambda f: (f.severity.value, f.title))),
            errors=tuple(str(e) for e in all_errors),
            metadata=ExecutionMetadata(
                node_count=len(explain.all_nodes),
                rules_run=len(self.rules) - len(all_errors),
                rules_failed=len(all_errors),
            ),
        )
    
    def _enhance_findings_with_sql(
        self,
        findings: list[Finding],
        query_info: QueryInfo,
    ) -> list[Finding]:
        """
        Enhance findings with SQL-based index recommendations.
        
        When we have the original SQL, we can provide much more specific
        recommendations for indexes, including composite indexes that
        cover filters, joins, and sorts together.
        """
        from querysense.analyzer.index_advisor import IndexRecommendation, IndexType
        
        enhanced: list[Finding] = []
        
        for finding in findings:
            # Only enhance SEQ_SCAN findings
            if finding.rule_id != "SEQ_SCAN_LARGE_TABLE":
                enhanced.append(finding)
                continue
            
            # Get table from finding
            table = finding.context.relation_name
            if not table:
                enhanced.append(finding)
                continue
            
            # Get recommended columns from SQL analysis
            columns = query_info.suggest_composite_index(table)
            
            if not columns:
                enhanced.append(finding)
                continue
            
            # Build enhanced suggestion
            rec = IndexRecommendation(
                table=table,
                columns=columns,
                index_type=IndexType.BTREE,
                estimated_improvement=finding.metrics.get("estimated_improvement", 1.0),
                reasoning=self._build_sql_reasoning(query_info, table, columns),
            )
            
            # Create new finding with enhanced suggestion
            enhanced_finding = finding.model_copy(update={
                "suggestion": rec.format_full(),
            })
            enhanced.append(enhanced_finding)
        
        return enhanced
    
    def _build_sql_reasoning(
        self,
        query_info: QueryInfo,
        table: str,
        columns: list[str],
    ) -> str:
        """Build reasoning based on SQL analysis."""
        parts: list[str] = ["Based on SQL query analysis:"]
        
        filter_cols = [
            c for c in query_info.filter_columns
            if c.table == table or c.table is None
        ]
        join_cols = [
            c for c in query_info.join_columns
            if c.table == table or c.table is None
        ]
        order_cols = [
            c for c in query_info.order_by_columns
            if c.table == table or c.table is None
        ]
        
        if filter_cols:
            equality = [c.column for c in filter_cols if c.is_equality]
            ranges = [c.column for c in filter_cols if c.is_range]
            if equality:
                parts.append(f"- Equality filters on: {', '.join(equality)}")
            if ranges:
                parts.append(f"- Range filters on: {', '.join(ranges)}")
        
        if join_cols:
            parts.append(f"- Join columns: {', '.join(c.column for c in join_cols)}")
        
        if order_cols:
            parts.append(f"- Sort columns: {', '.join(c.column for c in order_cols)}")
        
        parts.append("")
        parts.append(f"Recommended column order: {', '.join(columns)}")
        parts.append("(Equality columns first, then range, then sort)")
        
        return "\n".join(parts)
    
    def _run_rules_sequential(
        self,
        rules: list[Rule],
        explain: "ExplainOutput",
        prior_findings: list[Finding],
    ) -> tuple[list[Finding], list[Exception]]:
        """Run rules sequentially."""
        findings: list[Finding] = []
        errors: list[Exception] = []
        
        for rule in rules:
            try:
                rule_findings = self._run_rule(rule, explain, prior_findings)
                findings.extend(rule_findings[:self.max_findings_per_rule])
            except Exception as e:
                if self.fail_fast:
                    raise RuleError(rule.rule_id, rule.version, e) from e
                errors.append(e)
                logger.warning("Rule %s failed: %s", rule.rule_id, e)
        
        return findings, errors
    
    def _run_rules_parallel(
        self,
        rules: list[Rule],
        explain: "ExplainOutput",
        prior_findings: list[Finding],
    ) -> tuple[list[Finding], list[Exception]]:
        """Run rules in parallel using thread pool."""
        findings: list[Finding] = []
        errors: list[Exception] = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._run_rule, rule, explain, prior_findings): rule
                for rule in rules
            }
            
            for future in as_completed(futures):
                rule = futures[future]
                try:
                    rule_findings = future.result()
                    findings.extend(rule_findings[:self.max_findings_per_rule])
                except Exception as e:
                    if self.fail_fast:
                        raise RuleError(rule.rule_id, rule.version, e) from e
                    errors.append(e)
                    logger.warning("Rule %s failed: %s", rule.rule_id, e)
        
        return findings, errors
    
    def _run_rule(
        self,
        rule: Rule,
        explain: "ExplainOutput",
        prior_findings: list[Finding],
    ) -> list[Finding]:
        """Run a single rule."""
        return rule.analyze(explain, prior_findings)
