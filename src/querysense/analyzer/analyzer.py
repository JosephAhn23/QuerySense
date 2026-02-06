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

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from querysense.analyzer.errors import RuleError
from querysense.analyzer.fingerprint import AnalysisCache, PlanFingerprint
from querysense.analyzer.models import (
    AnalysisResult,
    ExecutionMetadata,
    Finding,
    RulePhase,
    Severity,
)
from querysense.analyzer.registry import get_registry
from querysense.analyzer.rules.base import Rule, SQLEnhanceable
from querysense.analyzer.sql_parser import QueryInfo, SQLQueryAnalyzer

if TYPE_CHECKING:
    from querysense.parser.models import ExplainOutput

logger = logging.getLogger(__name__)

# Thread-safe context variable for query info (fixes race condition)
_current_query_info: ContextVar[QueryInfo | None] = ContextVar(
    "current_query_info", default=None
)


def get_current_query_info() -> QueryInfo | None:
    """Get the current query info from context (thread-safe)."""
    return _current_query_info.get()


# =============================================================================
# Observability: Metrics and Tracing
# =============================================================================

@dataclass
class AnalyzerMetrics:
    """
    Structured metrics for analyzer observability.
    
    Provides production-ready metrics that can be exported to
    monitoring systems (Prometheus, Datadog, etc.)
    """
    
    # Counters
    analyses_total: int = 0
    findings_total: int = 0
    errors_total: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    
    # Histograms (store recent values for percentile calculation)
    analysis_durations_ms: list[float] = field(default_factory=list)
    findings_per_analysis: list[int] = field(default_factory=list)
    
    # Keep only last N samples for memory efficiency
    _max_samples: int = 1000
    
    def record_analysis(
        self,
        duration_ms: float,
        findings_count: int,
        errors_count: int,
        cache_hit: bool,
    ) -> None:
        """Record metrics for a completed analysis."""
        self.analyses_total += 1
        self.findings_total += findings_count
        self.errors_total += errors_count
        
        if cache_hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1
        
        # Maintain bounded history
        self.analysis_durations_ms.append(duration_ms)
        self.findings_per_analysis.append(findings_count)
        
        if len(self.analysis_durations_ms) > self._max_samples:
            self.analysis_durations_ms = self.analysis_durations_ms[-self._max_samples:]
        if len(self.findings_per_analysis) > self._max_samples:
            self.findings_per_analysis = self.findings_per_analysis[-self._max_samples:]
    
    @property
    def cache_hit_rate(self) -> float:
        """Cache hit rate (0.0 to 1.0)."""
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0
    
    @property
    def avg_duration_ms(self) -> float:
        """Average analysis duration in milliseconds."""
        if not self.analysis_durations_ms:
            return 0.0
        return sum(self.analysis_durations_ms) / len(self.analysis_durations_ms)
    
    @property
    def p95_duration_ms(self) -> float:
        """95th percentile analysis duration."""
        if not self.analysis_durations_ms:
            return 0.0
        sorted_durations = sorted(self.analysis_durations_ms)
        idx = int(len(sorted_durations) * 0.95)
        return sorted_durations[min(idx, len(sorted_durations) - 1)]
    
    def to_dict(self) -> dict[str, Any]:
        """Export metrics as dictionary for JSON/monitoring."""
        return {
            "analyses_total": self.analyses_total,
            "findings_total": self.findings_total,
            "errors_total": self.errors_total,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": self.cache_hit_rate,
            "avg_duration_ms": self.avg_duration_ms,
            "p95_duration_ms": self.p95_duration_ms,
        }


@dataclass
class TraceSpan:
    """A single span in a trace."""
    
    name: str
    start_time: float
    end_time: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    children: list["TraceSpan"] = field(default_factory=list)
    
    @property
    def duration_ms(self) -> float:
        """Duration in milliseconds."""
        if self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time) * 1000
    
    def end(self) -> None:
        """Mark span as complete."""
        self.end_time = time.perf_counter()
    
    def to_dict(self) -> dict[str, Any]:
        """Export span as dictionary."""
        return {
            "name": self.name,
            "duration_ms": self.duration_ms,
            "attributes": self.attributes,
            "children": [c.to_dict() for c in self.children],
        }


class Tracer:
    """
    Simple tracing for analyzer operations.
    
    Enables detailed performance analysis and debugging.
    Can be extended to export to OpenTelemetry, Jaeger, etc.
    """
    
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._root: TraceSpan | None = None
        self._stack: list[TraceSpan] = []
    
    def start_span(self, name: str, **attributes: Any) -> TraceSpan:
        """Start a new span."""
        span = TraceSpan(
            name=name,
            start_time=time.perf_counter(),
            attributes=attributes,
        )
        
        if self.enabled:
            if self._stack:
                self._stack[-1].children.append(span)
            else:
                self._root = span
            self._stack.append(span)
        
        return span
    
    def end_span(self) -> None:
        """End the current span."""
        if self.enabled and self._stack:
            self._stack[-1].end()
            self._stack.pop()
    
    def get_trace(self) -> dict[str, Any] | None:
        """Get the complete trace."""
        if self._root:
            return self._root.to_dict()
        return None


# Global metrics instance (can be replaced with custom instance)
_global_metrics = AnalyzerMetrics()


class Analyzer:
    """
    Simple rule-based query plan analyzer.
    
    Runs rules in two phases:
    1. PER_NODE rules: Analyze individual plan nodes
    2. AGGREGATE rules: Analyze patterns across findings
    
    Features:
    - Thread-safe: Uses contextvars for request-scoped state
    - Caching: Optional LRU cache for repeated analysis
    - Async: Supports both sync and async analysis
    - Observable: Built-in metrics and tracing
    
    Example:
        from querysense import parse_explain, Analyzer
        
        explain = parse_explain("plan.json")
        analyzer = Analyzer()
        result = analyzer.analyze(explain)
        
        for finding in result.findings:
            print(f"{finding.severity}: {finding.title}")
            if finding.suggestion:
                print(f"  Fix: {finding.suggestion}")
        
        # Async usage
        result = await analyzer.analyze_async(explain)
        
        # With caching
        analyzer = Analyzer(cache_enabled=True)
        result1 = analyzer.analyze(explain)  # Miss
        result2 = analyzer.analyze(explain)  # Hit
        print(f"Cache hit rate: {analyzer.metrics.cache_hit_rate:.1%}")
    """
    
    # Configuration constants (documented with rationale)
    DEFAULT_MAX_FINDINGS_PER_RULE: int = 100  # Prevent memory explosion from noisy rules
    DEFAULT_MAX_WORKERS: int = 4  # Balance parallelism vs thread overhead
    DEFAULT_CACHE_SIZE: int = 100  # Reasonable for typical usage patterns
    DEFAULT_CACHE_TTL: float = 300.0  # 5 minutes - plans may change
    
    def __init__(
        self,
        rules: list[Rule] | None = None,
        include_rules: set[str] | None = None,
        exclude_rules: set[str] | None = None,
        fail_fast: bool = False,
        max_findings_per_rule: int = DEFAULT_MAX_FINDINGS_PER_RULE,
        parallel: bool = True,
        max_workers: int = DEFAULT_MAX_WORKERS,
        # New: Caching options
        cache_enabled: bool = False,
        cache_size: int = DEFAULT_CACHE_SIZE,
        cache_ttl: float = DEFAULT_CACHE_TTL,
        # New: Observability options
        metrics: AnalyzerMetrics | None = None,
        tracing_enabled: bool = False,
    ) -> None:
        """
        Initialize the analyzer.
        
        Args:
            rules: Custom rules to use (if None, uses registry)
            include_rules: Only run these rule IDs
            exclude_rules: Skip these rule IDs
            fail_fast: Raise on first rule error
            max_findings_per_rule: Limit findings per rule (default: 100)
            parallel: Run rules in parallel
            max_workers: Thread pool size for parallel execution (default: 4)
            cache_enabled: Enable LRU caching of analysis results
            cache_size: Maximum number of cached results (default: 100)
            cache_ttl: Cache TTL in seconds (default: 300)
            metrics: Custom metrics instance (default: global metrics)
            tracing_enabled: Enable detailed tracing for debugging
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
        
        # Caching
        self.cache_enabled = cache_enabled
        self._cache: AnalysisCache | None = None
        if cache_enabled:
            self._cache = AnalysisCache(max_size=cache_size, ttl_seconds=cache_ttl)
        
        # Observability
        self.metrics = metrics if metrics is not None else _global_metrics
        self.tracing_enabled = tracing_enabled
    
    def analyze(
        self,
        explain: "ExplainOutput",
        sql: str | None = None,
    ) -> AnalysisResult:
        """
        Analyze an EXPLAIN output for performance issues.
        
        This method is thread-safe - multiple threads can call analyze()
        on the same Analyzer instance concurrently.
        
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
        tracer = Tracer(enabled=self.tracing_enabled)
        tracer.start_span("analyze", sql_provided=sql is not None)
        cache_hit = False
        
        try:
            # Check cache first
            fingerprint: PlanFingerprint | None = None
            if self.cache_enabled and self._cache is not None:
                tracer.start_span("fingerprint")
                fingerprint = PlanFingerprint.from_explain(explain)
                tracer.end_span()
                
                tracer.start_span("cache_lookup")
                cached = self._cache.get(fingerprint)
                tracer.end_span()
                
                if cached is not None:
                    cache_hit = True
                    duration_ms = (time.perf_counter() - start_time) * 1000
                    self.metrics.record_analysis(
                        duration_ms=duration_ms,
                        findings_count=len(cached.result.findings),
                        errors_count=len(cached.result.errors),
                        cache_hit=True,
                    )
                    logger.debug("Cache hit for fingerprint %s", fingerprint.full_hash[:8])
                    return cached.result
            
            # Parse SQL if provided for enhanced analysis
            query_info: QueryInfo | None = None
            if sql:
                tracer.start_span("sql_parse")
                try:
                    sql_analyzer = SQLQueryAnalyzer()
                    query_info = sql_analyzer.analyze(sql)
                    logger.debug(
                        "SQL parsed: %d tables, %d filter cols, %d join cols",
                        len(query_info.tables),
                        len(query_info.filter_columns),
                        len(query_info.join_columns),
                    )
                except Exception as e:
                    logger.warning("Failed to parse SQL query: %s", e)
                tracer.end_span()
            
            # Store query_info in context variable (thread-safe)
            token = _current_query_info.set(query_info)
            
            try:
                # Split rules by phase
                per_node_rules = [r for r in self.rules if r.phase == RulePhase.PER_NODE]
                aggregate_rules = [r for r in self.rules if r.phase == RulePhase.AGGREGATE]
                
                # Phase 1: PER_NODE rules
                tracer.start_span("phase1_per_node", rule_count=len(per_node_rules))
                if self.parallel and len(per_node_rules) > 1:
                    phase1_findings, phase1_errors = self._run_rules_parallel(
                        per_node_rules, explain, prior_findings=[]
                    )
                else:
                    phase1_findings, phase1_errors = self._run_rules_sequential(
                        per_node_rules, explain, prior_findings=[]
                    )
                tracer.end_span()
                
                # Phase 2: AGGREGATE rules (see phase 1 findings)
                tracer.start_span("phase2_aggregate", rule_count=len(aggregate_rules))
                phase2_findings, phase2_errors = self._run_rules_sequential(
                    aggregate_rules, explain, prior_findings=phase1_findings
                )
                tracer.end_span()
                
                # Combine results
                all_findings = phase1_findings + phase2_findings
                all_errors = phase1_errors + phase2_errors
                
                # Enhance findings with SQL-based recommendations if available
                if query_info:
                    tracer.start_span("enhance_with_sql")
                    all_findings = self._enhance_findings_with_sql(all_findings, query_info)
                    tracer.end_span()
                
            finally:
                # Reset context variable (thread-safe cleanup)
                _current_query_info.reset(token)
            
            # Build result
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            result = AnalysisResult(
                findings=tuple(sorted(all_findings, key=lambda f: (f.severity.value, f.title))),
                errors=tuple(str(e) for e in all_errors),
                metadata=ExecutionMetadata(
                    node_count=len(explain.all_nodes),
                    rules_run=len(self.rules) - len(all_errors),
                    rules_failed=len(all_errors),
                ),
            )
            
            # Cache the result
            if self.cache_enabled and self._cache is not None and fingerprint is not None:
                tracer.start_span("cache_store")
                self._cache.set(fingerprint, result)
                tracer.end_span()
            
            # Record metrics
            self.metrics.record_analysis(
                duration_ms=duration_ms,
                findings_count=len(result.findings),
                errors_count=len(result.errors),
                cache_hit=False,
            )
            
            return result
            
        finally:
            tracer.end_span()
            if self.tracing_enabled:
                trace = tracer.get_trace()
                if trace:
                    logger.debug("Analysis trace: %s", trace)
    
    async def analyze_async(
        self,
        explain: "ExplainOutput",
        sql: str | None = None,
    ) -> AnalysisResult:
        """
        Async version of analyze() for use in async applications.
        
        Runs the analysis in a thread pool to avoid blocking the event loop.
        Useful for web servers, APIs, and async applications.
        
        Args:
            explain: Parsed EXPLAIN output
            sql: Optional SQL query for enhanced analysis
            
        Returns:
            AnalysisResult with findings and metadata
            
        Example:
            async def handle_request(plan_json: str):
                explain = parse_explain(plan_json)
                result = await analyzer.analyze_async(explain)
                return result.findings
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,  # Use default executor
            lambda: self.analyze(explain, sql),
        )
    
    def _enhance_findings_with_sql(
        self,
        findings: list[Finding],
        query_info: QueryInfo,
    ) -> list[Finding]:
        """
        Enhance findings with SQL-based index recommendations.
        
        Uses the SQLEnhanceable protocol to delegate enhancement to rules
        that opt-in to SQL-based enhancement. This decouples the analyzer
        from specific rule implementations.
        
        When we have the original SQL, we can provide much more specific
        recommendations for indexes, including composite indexes that
        cover filters, joins, and sorts together.
        """
        # Build rule lookup by ID for O(1) access
        rule_by_id: dict[str, Rule] = {rule.rule_id: rule for rule in self.rules}
        
        enhanced: list[Finding] = []
        
        for finding in findings:
            rule = rule_by_id.get(finding.rule_id)
            
            # Check if rule implements SQLEnhanceable protocol
            if rule is not None and isinstance(rule, SQLEnhanceable):
                try:
                    enhanced_finding = rule.enhance_with_sql(finding, query_info)
                    enhanced.append(enhanced_finding)
                except Exception as e:
                    logger.warning(
                        "Rule %s failed to enhance finding with SQL: %s",
                        finding.rule_id,
                        e,
                    )
                    enhanced.append(finding)
            else:
                # Rule doesn't support SQL enhancement, use fallback
                enhanced_finding = self._default_sql_enhancement(finding, query_info)
                enhanced.append(enhanced_finding)
        
        return enhanced
    
    def _default_sql_enhancement(
        self,
        finding: Finding,
        query_info: QueryInfo,
    ) -> Finding:
        """
        Default SQL enhancement for rules that don't implement SQLEnhanceable.
        
        Provides generic index recommendations for sequential scan findings.
        This is a fallback for backward compatibility.
        """
        from querysense.analyzer.index_advisor import IndexRecommendation, IndexType
        
        # Only enhance scan-type findings by default
        if "SCAN" not in finding.rule_id:
            return finding
        
        # Get table from finding
        table = finding.context.relation_name
        if not table:
            return finding
        
        # Get recommended columns from SQL analysis
        columns = query_info.suggest_composite_index(table)
        
        if not columns:
            return finding
        
        # Build enhanced suggestion
        rec = IndexRecommendation(
            table=table,
            columns=columns,
            index_type=IndexType.BTREE,
            estimated_improvement=finding.metrics.get("estimated_improvement", 1.0),
            reasoning=self._build_sql_reasoning(query_info, table, columns),
        )
        
        # Create new finding with enhanced suggestion
        return finding.model_copy(update={
            "suggestion": rec.format_full(),
        })
    
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
