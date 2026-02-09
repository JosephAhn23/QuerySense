"""
Stateless analysis endpoint.

POST /api/v1/analyze — analyze a plan without storing it.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, status

from querysense.cloud.services import analyze_plan_to_dict

router = APIRouter()


class AnalyzeRequest(BaseModel):
    """Request body for stateless analysis."""

    plan_json: str = Field(..., description="EXPLAIN (FORMAT JSON) output as a string")
    sql: str | None = Field(default=None, description="Optional SQL query text")


@router.post("/analyze", summary="Analyze an EXPLAIN plan (stateless)")
async def analyze(body: AnalyzeRequest) -> dict:
    """
    Analyze an EXPLAIN JSON plan and return the findings.

    This endpoint does NOT store the plan or result.
    Useful for one-off analysis or CI integration.
    """
    try:
        result = analyze_plan_to_dict(body.plan_json, body.sql)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to parse or analyze plan: {exc}",
        ) from exc

    return result
