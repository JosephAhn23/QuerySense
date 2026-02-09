"""
Temporal Intelligence: plan history, change-point detection, drift analysis.

Provides:
- IR-based plan fingerprinting over time
- Change-point detection (PELT algorithm) for regression identification
- Drift classification: plan regression vs data drift vs environmental shift
"""

from querysense.temporal.store import (
    PlanSnapshot,
    TemporalStore,
    InMemoryTemporalStore,
)
from querysense.temporal.changepoint import (
    Changepoint,
    detect_changepoints,
    pelt_changepoints,
)
from querysense.temporal.drift import (
    DriftType,
    DriftEvent,
    DriftAnalyzer,
)

__all__ = [
    "PlanSnapshot",
    "TemporalStore",
    "InMemoryTemporalStore",
    "Changepoint",
    "detect_changepoints",
    "pelt_changepoints",
    "DriftType",
    "DriftEvent",
    "DriftAnalyzer",
]
