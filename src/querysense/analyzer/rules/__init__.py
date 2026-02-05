"""Analyzer rules module - individual detection rules."""

from querysense.analyzer.rules.base import Rule, RuleConfig, discover_rules
from querysense.analyzer.rules.bad_row_estimate import BadRowEstimate
from querysense.analyzer.rules.correlated_subquery import CorrelatedSubquery
from querysense.analyzer.rules.excessive_seq_scans import ExcessiveSeqScans
from querysense.analyzer.rules.missing_buffers import MissingBuffers
from querysense.analyzer.rules.nested_loop_large_table import NestedLoopLargeTable
from querysense.analyzer.rules.parallel_query_not_used import ParallelQueryNotUsed
from querysense.analyzer.rules.seq_scan_large_table import SeqScanLargeTable
from querysense.analyzer.rules.spilling_to_disk import SpillingToDisk

__all__ = [
    "Rule",
    "RuleConfig",
    "discover_rules",
    # Individual rules
    "BadRowEstimate",
    "CorrelatedSubquery",
    "ExcessiveSeqScans",
    "MissingBuffers",
    "NestedLoopLargeTable",
    "ParallelQueryNotUsed",
    "SeqScanLargeTable",
    "SpillingToDisk",
]
