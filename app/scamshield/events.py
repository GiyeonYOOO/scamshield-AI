"""F3012: safe execution events, independent of subscribers."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import hmac
from secrets import token_bytes
from threading import Lock
from types import MappingProxyType
from typing import Callable, Mapping
from uuid import uuid4


TOOLS = {"google_safe_browsing", "virustotal_url", "virustotal_domain", "urlscan_history"}
CHOICES = TOOLS | {"general_conversation", "ask_for_public_url", "use_previous_url",
                   "finish_without_lookup", "prioritize_action", "describe_message_context"}
REASONS = {"known_threat_lookup", "exact_url_report", "host_reputation", "recent_scan_history",
           "alternative_evidence"}
OUTCOMES = {
    "MATCH", "NO_MATCH", "REPORT", "INCOMPLETE_REPORT", "CANDIDATES", "NO_CANDIDATES",
    "NO_RECORD", "MISSING_KEY", "AUTH_ERROR", "INVALID_INPUT", "REQUEST_REJECTED",
    "RATE_LIMIT", "TIMEOUT", "NETWORK_ERROR", "UPSTREAM_ERROR", "INVALID_RESPONSE",
    "LLM_NETWORK_ERROR", "LLM_AUTH_ERROR", "LLM_RATE_LIMIT", "LLM_HTTP_ERROR",
    "LLM_INVALID_RESPONSE", "LLM_NO_VALID_CHOICE", "LLM_REJECTED_CHOICE", "INVALID_LLM_ENDPOINT",
    "LLM_TIMEOUT", "LLM_OUTPUT_TRUNCATED", "LLM_OUTPUT_FILTERED", "LLM_UNSUPPORTED_CALL_FORMAT",
    "LLM_TOOL_CALL_MISSING", "LLM_UNKNOWN_TOOL", "LLM_INVALID_ARGUMENTS",
    "LLM_CONTEXT_SCHEMA_INVALID", "LLM_CONTEXT_REFERENCE_INVALID", "LLM_NOT_CONFIGURED", "LLM_NOT_ENOUGH_TEXT",
    "UNEXPECTED_TOOL_ERROR", "UNEXPECTED_NODE_ERROR", "UNEXPECTED_RUN_ERROR",
}
STOPS = {"UNAVAILABLE_CONFIGURATION", "EVIDENCE_COLLECTED", "NO_MORE_ALTERNATIVES",
         "REPLAN_LIMIT", "LLM_NO_USEFUL_ALTERNATIVE", "CONSTRAINTS_UNMET", "COVERAGE_INCOMPLETE",
         "WORKER_REQUESTED_CHANGE", "AUDIT_ANOMALY"}
AUDIT_CODES = {"UNPLANNED_TOOL", "MISSING_OR_EXTRA_ATTEMPT", "DUPLICATE_CALL",
               "RETRY_LIMIT", "FIXED_ARGUMENT_CHANGED", "REPLAN_LIMIT", "PLAN_ORDER",
               "INCOMPLETE_REPORT", "UNDECLARED_RETRY"}
SCHEMA = {
    "run.started": {"max_replans": int},
    "run.finished": {"status": {"completed", "failed"}, "replans": int},
    "node.entered": {"node": {"analyze", "plan", "execute", "judge", "replan", "respond"}},
    "node.finished": {"node": {"analyze", "plan", "execute", "judge", "replan", "respond"},
                      "status": {"completed", "failed"}},
    "tool.requested": {"tool": TOOLS, "target_scope": {"url", "host"}, "days": int},
    "tool.finished": {"tool": TOOLS, "outcome": OUTCOMES, "duration_ms": int, "ok": bool},
    "llm.decision": {"stage": {"intent_and_plan", "replan", "response", "message_context"}, "choice": CHOICES,
                     "reason": REASONS},
    "message_context.finished": {"status": {"analyzed", "cache_hit", "rules_only"}, "reason": OUTCOMES,
                                 "duration_ms": int, "http_status": int},
    "replan.decided": {"performed": bool, "reason": STOPS, "tool": TOOLS, "count": int,
                       "source": {"llm", "rules"}},
    "response.generated": {"status": {"GENERAL", "KNOWN_RISK", "SUSPICIOUS", "NO_KNOWN_MATCH",
                                      "INSUFFICIENT_EVIDENCE"}},
    "error.handled": {"code": OUTCOMES, "handling": {"rules_fallback", "continue", "propagated"}},
    "planner.task": {"task_id": int, "revision": int, "tool": TOOLS, "days": int,
                     "fixed_url": bool, "fixed_days": bool},
    "worker.attempt": {"task_id": int, "tool": TOOLS, "attempt": int, "days": int},
    "worker.decision": {"task_id": int, "action": {"complete", "retry_same_tool", "skip_task", "request_new_plan"},
                        "llm_called": bool, "retried": bool, "request_plan_change": bool, "outcome": OUTCOMES},
    "audit.checked": {"status": {"verified", "anomaly", "needs_review"}, "code": AUDIT_CODES,
                      "request_plan_change": bool, "llm_called": bool, "revision": int},
}
INPUT_REFERENCE_EVENTS = {"planner.task", "tool.requested"}


def session_reference(session_id: str) -> str:
    return sha256(session_id.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ExecutionEvent:
    session_id: str
    run_id: str
    sequence: int
    occurred_at: str
    event_type: str
    data: Mapping[str, str | int | bool]


class EventBus:
    def __init__(self):
        self._subscribers: list[Callable[[ExecutionEvent], None]] = []
        self._lock = Lock()

    def subscribe(self, subscriber: Callable[[ExecutionEvent], None]) -> None:
        with self._lock:
            self._subscribers.append(subscriber)

    def publish(self, event: ExecutionEvent) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber(event)
            except Exception:
                # Subscriber failures must stay outside the analysis path.
                continue


@dataclass
class RunEvents:
    bus: EventBus
    session_id: str
    run_id: str = field(default_factory=lambda: uuid4().hex)
    sequence: int = 0
    audit_events: list[ExecutionEvent] = field(default_factory=list, repr=False)
    _reference_key: bytes = field(default_factory=lambda: token_bytes(32), repr=False)

    def emit(self, event_type: str, *, input_url=None, **data) -> None:
        fields = SCHEMA[event_type]
        payload = {}
        for name, allowed in fields.items():
            value = data.get(name)
            if (type(value) is allowed if isinstance(allowed, type)
                else isinstance(value, str) and value in allowed):
                payload[name] = value
        if event_type in INPUT_REFERENCE_EVENTS and isinstance(input_url, str):
            payload["input_ref"] = hmac.digest(self._reference_key, input_url.encode("utf-8"), "sha256").hex()
        self.sequence += 1
        event = ExecutionEvent(
            self.session_id, self.run_id, self.sequence,
            datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            event_type, MappingProxyType(payload),
        )
        if event_type in {"worker.attempt", "tool.requested", "tool.finished"}:
            self.audit_events.append(event)
        self.bus.publish(event)
