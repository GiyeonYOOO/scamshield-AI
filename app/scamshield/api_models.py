"""F3017 request and response schemas."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StringConstraints, model_validator

from .plan_models import TargetType


Identifier = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
Title = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
Action = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]
ScheduleDate = Annotated[str, StringConstraints(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")]
ScheduleTime = Annotated[str, StringConstraints(pattern=r"^[0-9]{2}:[0-9]{2}(:[0-9]{2})?$")]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ErrorInfo(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{
        "error": {"code": "SESSION_REQUIRED", "message": "먼저 분석 요청으로 세션을 시작하세요."},
    }]})
    error: ErrorInfo


class CallContext(Input):
    request: Literal["transfer", "code", "id_photo", "app", "other"]
    verification: Literal["no", "yes", "denied"]
    already_sent: StrictBool = False


class ChatRequest(Input):
    message: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]
    target_type: TargetType = "url"
    context_analysis: StrictBool = False
    context_note: Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000)] | None = None
    call_context: CallContext | None = None
    model_config = ConfigDict(json_schema_extra={"examples": [
        {"message": "https://example.com/ 검사해 주세요.", "target_type": "url"},
        {"message": "같은 링크인데 최근 24시간 이내 기록만 확인해 주세요."},
    ]})


class ExclusionReason(BaseModel):
    code: str
    message: str


class Evidence(BaseModel):
    tool: str
    source: str
    outcome: str
    scope: str
    signal: str | None = None
    observed_at: str | None = None
    age_hours: float | None = None
    scope_met: bool
    freshness_met: bool
    eligible: bool
    exclusion_reasons: list[ExclusionReason] = Field(default_factory=list)
    supplemental_search: bool = False
    requested_search_days: int | None = None
    searched_days: int | None = None
    candidate_pages: int | None = None
    candidate_more_available: bool = False
    supplemental_candidate_id: str | None = None
    threat_types: list[str] | None = None
    engine_counts: dict[str, int] | None = None
    reported_engines: int | None = None
    detection_strength: Literal["single_engine", "multiple_engines"] | None = None
    scan_id: str | None = None


class Decision(BaseModel):
    stage: str
    source: Literal["llm", "rules"]
    choices: list[str] = Field(default_factory=list)
    fallback: str | None = None


class MessageFinding(BaseModel):
    label: str
    quote: str
    source: Literal["llm", "rules"]


class MessageContext(BaseModel):
    status: Literal["analyzed", "rules_only"]
    reason: str | None = None
    facts: list[MessageFinding]
    signals: list[MessageFinding]
    unknowns: list[str]
    checks: list[str]
    actions: list[str]


class TextAssessment(BaseModel):
    status: Literal["signals_found", "no_signals_found"]
    url_lookup: Literal["attempted", "not_attempted"]
    context: MessageContext | None = None


class Analysis(BaseModel):
    status: Literal["GENERAL", "KNOWN_RISK", "SUSPICIOUS", "NO_KNOWN_MATCH", "INSUFFICIENT_EVIDENCE"]
    message: str
    issue: str | None = None
    conditions: dict[str, int | bool] = Field(default_factory=dict)
    constraints_met: bool | None = None
    freshness_hours: int | None = None
    minimum_observed_at: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    highlighted_evidence: Evidence | None = None
    local_signals: list[str] = Field(default_factory=list)
    text_assessment: TextAssessment | None = None
    message_context: MessageContext | None = None
    provider_comparison: Literal["agreement", "different", "scope_differs"] | None = None
    actions: list[str] = Field(default_factory=list)
    decisions: list[Decision] = Field(default_factory=list)
    assessment_source: Literal["rules"] = "rules"
    tool_outcomes: dict[str, str] = Field(default_factory=dict)
    tool_errors: dict[str, str] = Field(default_factory=dict)
    llm_error: str | None = None
    replans: int = 0
    stop_reason: str | None = None


class PlanDraftResponse(BaseModel):
    analysis_id: Identifier
    target_type: TargetType
    actions: list[str]


FollowUpQuestionId = Literal["requested_info", "interaction", "source"]


class FollowUpOption(BaseModel):
    id: str
    label: str


class FollowUpQuestion(BaseModel):
    id: FollowUpQuestionId
    prompt: str
    options: list[FollowUpOption]


class FollowUpAnswer(Input):
    question_id: FollowUpQuestionId
    answer: Literal["id_photo", "otp", "credentials", "payment", "install", "other", "none",
                    "unsure", "no_action", "viewed", "shared", "paid", "installed",
                    "confirmed", "denied", "not_checked", "skip"]


class FollowUpResponse(BaseModel):
    status: Literal["asking", "completed", "skipped"]
    question: FollowUpQuestion | None
    answered_count: int
    max_questions: int
    actions: list[str]
    original_verdict: str


class ChatResponse(BaseModel):
    run_id: Identifier
    status: Literal["completed", "partial"]
    analysis: Analysis
    plan_draft: PlanDraftResponse | None
    follow_up: FollowUpResponse | None = None


class PlanCreate(Input):
    analysis_id: Identifier | None = None
    title: Title
    actions: Annotated[list[Action], Field(min_length=1, max_length=20)] | None = None
    execution_date: ScheduleDate | None = None
    start_time: ScheduleTime | None = None
    end_time: ScheduleTime | None = None
    model_config = ConfigDict(json_schema_extra={"examples": [
        {"title": "공식 연락처로 확인", "actions": ["기관의 대표번호로 연락하기"]},
        {"analysis_id": "0123456789abcdef0123456789abcdef", "title": "공식 연락처로 확인"},
    ]})

    @model_validator(mode="after")
    def valid_source(self):
        if (self.analysis_id is None) == (self.actions is None):
            raise ValueError("provide analysis_id or actions")
        if self.analysis_id is None and any((self.execution_date, self.start_time, self.end_time)):
            raise ValueError("manual posts do not use a schedule")
        return self


class PlanPatch(Input):
    title: Title | None = None
    actions: Annotated[list[Action], Field(min_length=1, max_length=20)] | None = None
    execution_date: ScheduleDate | None = None
    start_time: ScheduleTime | None = None
    end_time: ScheduleTime | None = None
    model_config = ConfigDict(json_schema_extra={"examples": [{"start_time": "09:30", "end_time": "10:30"}]})

    @model_validator(mode="after")
    def changes_required(self):
        if not self.model_fields_set or any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("at least one non-null change is required")
        return self


class PlanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, json_schema_extra={"examples": [{
        "id": "abcdef0123456789abcdef0123456789",
        "analysis_id": "0123456789abcdef0123456789abcdef",
        "title": "공식 연락처로 확인", "target_type": "url",
        "actions": ["기관의 공식 앱에서 알림을 확인하세요."],
        "execution_date": "2026-11-18", "start_time": "09:00:00", "end_time": "10:00:00",
        "created_at": "2026-11-18T00:00:00+00:00", "updated_at": "2026-11-18T00:00:00+00:00",
    }]})
    id: Identifier
    analysis_id: Identifier | None
    title: str
    target_type: TargetType
    actions: list[str]
    execution_date: str | None
    start_time: str | None
    end_time: str | None
    created_at: str
    updated_at: str


class PlanSaved(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    plan: PlanResponse
    has_overlap: bool
    overlapping_plan_ids: list[Identifier]


class LogSummary(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{
        "run_id": "0123456789abcdef0123456789abcdef",
        "started_at": "2026-11-18T00:00:00+00:00",
        "ended_at": "2026-11-18T00:00:01+00:00", "event_count": 18,
    }]})
    run_id: Identifier
    started_at: str
    ended_at: str | None
    event_count: int


class LogEvent(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{
        "run_id": "0123456789abcdef0123456789abcdef", "sequence": 1,
        "occurred_at": "2026-11-18T00:00:00+00:00", "event_type": "run.started", "data": {},
    }]})
    run_id: Identifier
    sequence: int
    occurred_at: str
    event_type: str
    data: dict[str, str | int | bool]


class LogDetail(BaseModel):
    run_id: Identifier
    events: list[LogEvent]


class WarningLocation(BaseModel):
    revision: int
    sequence: int


class LogWarning(BaseModel):
    code: str
    location: WarningLocation
    reason: str
    evidence_event_ids: list[str]


class LogDiagnosis(BaseModel):
    status: Literal["pending", "completed", "failed"]
    component: Literal["Planner", "Worker", "Tool"] | None = None
    evidence_code: str | None = None
    evidence_event_ids: list[str] = Field(default_factory=list)
    text: str | None = None
    error_code: str | None = None


class LogEvaluation(BaseModel):
    run_id: Identifier
    status: Literal["normal", "warning", "inconclusive"]
    warnings: list[LogWarning]
    complete: bool
    reason: str | None = None
    diagnosis: LogDiagnosis | None = None
