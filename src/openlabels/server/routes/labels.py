"""
Sensitivity label management API endpoints.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openlabels.server.db import get_session
from openlabels.server.models import SensitivityLabel, LabelRule, ScanResult
from openlabels.auth.dependencies import get_current_user, require_admin

router = APIRouter()


class LabelResponse(BaseModel):
    """Sensitivity label response."""

    id: str
    name: str
    description: Optional[str]
    priority: Optional[int]
    color: Optional[str]
    parent_id: Optional[str]

    class Config:
        from_attributes = True


class LabelRuleCreate(BaseModel):
    """Request to create a label rule."""

    rule_type: str  # 'risk_tier' | 'entity_type'
    match_value: str  # 'CRITICAL' | 'SSN'
    label_id: str
    priority: int = 0


class LabelRuleResponse(BaseModel):
    """Label rule response."""

    id: UUID
    rule_type: str
    match_value: str
    label_id: str
    label_name: Optional[str] = None
    priority: int

    class Config:
        from_attributes = True


class ApplyLabelRequest(BaseModel):
    """Request to apply a label to a file."""

    result_id: UUID
    label_id: str


@router.get("", response_model=list[LabelResponse])
async def list_labels(
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """List available sensitivity labels."""
    query = select(SensitivityLabel).where(
        SensitivityLabel.tenant_id == user.tenant_id
    ).order_by(SensitivityLabel.priority)
    result = await session.execute(query)
    labels = result.scalars().all()
    return [LabelResponse.model_validate(l) for l in labels]


@router.post("/sync", status_code=202)
async def sync_labels(
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Sync sensitivity labels from Microsoft 365."""
    # TODO: Implement Graph API call to fetch labels
    return {"message": "Label sync initiated"}


@router.get("/rules", response_model=list[LabelRuleResponse])
async def list_label_rules(
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    """List label mapping rules."""
    query = select(LabelRule).where(
        LabelRule.tenant_id == user.tenant_id
    ).order_by(LabelRule.priority.desc())
    result = await session.execute(query)
    rules = result.scalars().all()

    # Enrich with label names
    responses = []
    for rule in rules:
        label = await session.get(SensitivityLabel, rule.label_id)
        response = LabelRuleResponse.model_validate(rule)
        if label:
            response.label_name = label.name
        responses.append(response)

    return responses


@router.post("/rules", response_model=LabelRuleResponse, status_code=201)
async def create_label_rule(
    request: LabelRuleCreate,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Create a label mapping rule."""
    if request.rule_type not in ("risk_tier", "entity_type"):
        raise HTTPException(status_code=400, detail="Invalid rule type")

    # Verify label exists
    label = await session.get(SensitivityLabel, request.label_id)
    if not label or label.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Label not found")

    rule = LabelRule(
        tenant_id=user.tenant_id,
        rule_type=request.rule_type,
        match_value=request.match_value,
        label_id=request.label_id,
        priority=request.priority,
        created_by=user.id,
    )
    session.add(rule)
    await session.flush()

    response = LabelRuleResponse.model_validate(rule)
    response.label_name = label.name
    return response


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_label_rule(
    rule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Delete a label rule."""
    rule = await session.get(LabelRule, rule_id)
    if not rule or rule.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule not found")

    await session.delete(rule)


@router.post("/apply", status_code=202)
async def apply_label(
    request: ApplyLabelRequest,
    session: AsyncSession = Depends(get_session),
    user=Depends(require_admin),
):
    """Apply a sensitivity label to a file."""
    result = await session.get(ScanResult, request.result_id)
    if not result or result.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Result not found")

    label = await session.get(SensitivityLabel, request.label_id)
    if not label or label.tenant_id != user.tenant_id:
        raise HTTPException(status_code=404, detail="Label not found")

    # TODO: Enqueue labeling job
    return {
        "message": "Label application queued",
        "result_id": request.result_id,
        "label_id": request.label_id,
    }
