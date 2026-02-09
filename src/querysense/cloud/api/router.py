"""
Main API router — aggregates all /api/v1 sub-routers.
"""

from __future__ import annotations

from fastapi import APIRouter

from querysense.cloud.api.analyze import router as analyze_router
from querysense.cloud.api.keys import router as keys_router
from querysense.cloud.api.plans import router as plans_router
from querysense.cloud.api.share import router as share_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(analyze_router, tags=["analyze"])
api_router.include_router(plans_router, tags=["plans"])
api_router.include_router(share_router, tags=["share"])
api_router.include_router(keys_router, tags=["keys"])
