"""
Plan fingerprinting for caching.

Simple, stable identifiers for query plans to enable:
- Caching analysis results across runs
- Detecting if a plan has changed
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from querysense.analyzer.models import AnalysisResult
    from querysense.parser.models import ExplainOutput

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PlanFingerprint:
    """
    Stable identifier for a query plan.
    
    Used for caching - if fingerprint matches, plan is the same.
    """
    
    query_hash: str       # Hash of query text
    structure_hash: str   # Hash of plan structure (node types)
    data_hash: str        # Hash of row counts and costs
    node_count: int = 0
    
    @classmethod
    def from_explain(cls, explain: "ExplainOutput") -> "PlanFingerprint":
        """Create fingerprint from EXPLAIN output."""
        # Hash query text
        query_text = explain.query_text or ""
        query_hash = hashlib.sha256(query_text.encode()).hexdigest()[:16]
        
        # Hash structure (node types and relations)
        structure_parts = []
        for node in explain.iter_nodes():
            structure_parts.append(f"{node.node_type}:{node.relation_name or ''}")
        structure_hash = hashlib.sha256(
            "|".join(structure_parts).encode()
        ).hexdigest()[:16]
        
        # Hash data (row counts, costs)
        data_parts = []
        for node in explain.iter_nodes():
            data_parts.append(f"{node.actual_rows}:{node.total_cost:.2f}")
        data_hash = hashlib.sha256(
            "|".join(data_parts).encode()
        ).hexdigest()[:16]
        
        return cls(
            query_hash=query_hash,
            structure_hash=structure_hash,
            data_hash=data_hash,
            node_count=len(explain.all_nodes),
        )
    
    @property
    def full_hash(self) -> str:
        """Full hash combining all components."""
        combined = f"{self.query_hash}:{self.structure_hash}:{self.data_hash}"
        return hashlib.sha256(combined.encode()).hexdigest()[:32]
    
    def diff(self, other: "PlanFingerprint") -> "PlanDiff":
        """Compare with another fingerprint."""
        return PlanDiff(
            query_changed=(self.query_hash != other.query_hash),
            structure_changed=(self.structure_hash != other.structure_hash),
            data_changed=(self.data_hash != other.data_hash),
        )


@dataclass
class PlanDiff:
    """Difference between two plan fingerprints."""
    
    query_changed: bool
    structure_changed: bool
    data_changed: bool
    
    @property
    def is_identical(self) -> bool:
        """True if plans are exactly the same."""
        return not (self.query_changed or self.structure_changed or self.data_changed)
    
    @property
    def needs_reanalysis(self) -> bool:
        """True if we need to re-run analysis."""
        return self.query_changed or self.structure_changed


@dataclass
class CachedAnalysis:
    """Cached analysis result."""
    
    fingerprint: PlanFingerprint
    result: "AnalysisResult"
    cached_at: float = field(default_factory=time.time)
    
    def is_expired(self, ttl_seconds: float) -> bool:
        """Check if cache entry has expired."""
        return (time.time() - self.cached_at) > ttl_seconds


class AnalysisCache:
    """
    Simple in-memory LRU cache for analysis results.
    
    Example:
        cache = AnalysisCache(max_size=100, ttl_seconds=300)
        
        fingerprint = PlanFingerprint.from_explain(explain)
        cached = cache.get(fingerprint)
        
        if cached:
            return cached.result
        
        result = analyzer.analyze(explain)
        cache.set(fingerprint, result)
    """
    
    def __init__(
        self,
        max_size: int = 100,
        ttl_seconds: float = 300.0,  # 5 minutes
    ) -> None:
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, CachedAnalysis] = OrderedDict()
        self._hits = 0
        self._misses = 0
    
    def get(self, fingerprint: PlanFingerprint) -> CachedAnalysis | None:
        """Get cached result if available and not expired."""
        key = fingerprint.full_hash
        
        if key in self._cache:
            cached = self._cache[key]
            
            if cached.is_expired(self.ttl_seconds):
                del self._cache[key]
                self._misses += 1
                return None
            
            # Move to end (LRU)
            self._cache.move_to_end(key)
            self._hits += 1
            return cached
        
        self._misses += 1
        return None
    
    def set(self, fingerprint: PlanFingerprint, result: "AnalysisResult") -> None:
        """Cache an analysis result."""
        key = fingerprint.full_hash
        
        # Evict oldest if at capacity
        while len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)
        
        self._cache[key] = CachedAnalysis(
            fingerprint=fingerprint,
            result=result,
        )
    
    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()
        self._hits = 0
        self._misses = 0
    
    @property
    def hit_rate(self) -> float:
        """Cache hit rate (0.0 to 1.0)."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0
    
    @property
    def size(self) -> int:
        """Current number of cached entries."""
        return len(self._cache)
