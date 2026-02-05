"""Analyzer rules module - individual detection rules."""

from querysense.analyzer.rules.base import Rule, RuleConfig, discover_rules
from querysense.analyzer.rules.excessive_seq_scans import ExcessiveSeqScans
from querysense.analyzer.rules.seq_scan_large_table import SeqScanLargeTable

__all__ = [
    "Rule",
    "RuleConfig",
    "discover_rules",
    "SeqScanLargeTable",
    "ExcessiveSeqScans",
]
