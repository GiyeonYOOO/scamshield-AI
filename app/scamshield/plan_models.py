"""Trusted Agent drafts and saved prevention plan values."""

from dataclasses import dataclass
from typing import Literal


TargetType = Literal["url", "text", "screenshot"]
TARGET_TYPES = {"url", "text", "screenshot"}


@dataclass(frozen=True)
class AnalysisPlanDraft:
    """In-process conversion of a completed Agent response."""

    owner_reference: str
    analysis_id: str
    target_type: TargetType
    actions: tuple[str, ...]


@dataclass(frozen=True)
class PreventionPlan:
    id: str
    owner_reference: str
    analysis_id: str | None
    title: str
    target_type: TargetType
    actions: tuple[str, ...]
    execution_date: str | None
    start_time: str | None
    end_time: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class PlanSaveResult:
    plan: PreventionPlan
    overlapping_plan_ids: tuple[str, ...]

    @property
    def has_overlap(self) -> bool:
        return bool(self.overlapping_plan_ids)
