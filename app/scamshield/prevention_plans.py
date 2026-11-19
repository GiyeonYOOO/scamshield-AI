"""F3015/F3016: explicit SQLite storage and owner-scoped plan management."""

from datetime import date, datetime, time, timezone
import json
from pathlib import Path
import re
import sqlite3
from threading import Lock
from uuid import uuid4

from .events import session_reference
from .plan_models import AnalysisPlanDraft, PlanSaveResult, PreventionPlan, TARGET_TYPES


PLAN_TABLE = """
CREATE TABLE IF NOT EXISTS prevention_plans (
    id TEXT PRIMARY KEY NOT NULL,
    owner_reference TEXT NOT NULL,
    analysis_id TEXT,
    title TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('url', 'text', 'screenshot')),
    actions TEXT NOT NULL,
    execution_date TEXT,
    start_time TEXT,
    end_time TEXT CHECK (start_time < end_time),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)
"""
PLAN_INDEX = """
CREATE INDEX IF NOT EXISTS prevention_plans_schedule
ON prevention_plans(owner_reference, execution_date, start_time, end_time);
"""

SENSITIVE_TEXT = re.compile(
    r"(?:[a-z][a-z0-9+.-]*://|www\.)\S+|[\w.+-]+@[\w.-]+\.[a-z]{2,}"
    r"|\b(?:token|password|api[_-]?key)\s*[:=]\s*[^\s,;]+",
    re.IGNORECASE,
)


def _owner(owner_id: str) -> str:
    if not isinstance(owner_id, str) or not owner_id.strip():
        raise ValueError("owner_id is required")
    return session_reference(owner_id)


def _display_text(value: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError("plan text must be a string")
    value = value.strip()
    if not 1 <= len(value) <= maximum:
        raise ValueError("invalid plan text length")
    return SENSITIVE_TEXT.sub("[가림]", value)


def _actions(values) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 20:
        raise ValueError("between 1 and 20 actions are required")
    return tuple(_display_text(value, 500) for value in values)


def _schedule(execution_date: date | str | None, start_time: time | str | None, end_time: time | str | None):
    if (execution_date, start_time, end_time) == (None, None, None):
        return None, None, None
    if isinstance(execution_date, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", execution_date):
        execution_date = date.fromisoformat(execution_date)
    if type(execution_date) is not date:
        raise ValueError("execution_date must be YYYY-MM-DD")

    def wall_time(value):
        if isinstance(value, str) and re.fullmatch(r"[0-9]{2}:[0-9]{2}(?::[0-9]{2})?", value):
            value = time.fromisoformat(value)
        if not isinstance(value, time) or value.tzinfo is not None or value.microsecond:
            raise ValueError("time must be HH:MM or HH:MM:SS without timezone")
        return value.isoformat(timespec="seconds")

    starts, ends = wall_time(start_time), wall_time(end_time)
    if starts >= ends:
        raise ValueError("end_time must be later than start_time on the same date")
    return execution_date.isoformat(), starts, ends


def _as_plan(row: sqlite3.Row) -> PreventionPlan:
    values = dict(row)
    values["actions"] = tuple(json.loads(values["actions"]))
    return PreventionPlan(**values)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class PreventionPlans:
    """Accept trusted session IDs and Agent drafts from application code."""

    def __init__(self, path: str | Path):
        self._lock = Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        try:
            with self._db:
                self._db.execute("BEGIN IMMEDIATE")
                self._db.execute(PLAN_TABLE)
                columns = self._db.execute("PRAGMA table_info(prevention_plans)").fetchall()
                if any(column["name"] == "analysis_id" and column["notnull"] for column in columns):
                    self._db.execute("ALTER TABLE prevention_plans RENAME TO prevention_plans_legacy")
                    self._db.execute(PLAN_TABLE)
                    names = ", ".join(column["name"] for column in columns)
                    self._db.execute(f"INSERT INTO prevention_plans ({names}) SELECT {names} FROM prevention_plans_legacy")
                    self._db.execute("DROP TABLE prevention_plans_legacy")
                self._db.execute(PLAN_INDEX)
        except sqlite3.Error:
            self._db.close()
            raise

    def _get(self, owner, plan_id):
        return self._db.execute(
            "SELECT * FROM prevention_plans WHERE owner_reference = ? AND id = ?", (owner, plan_id),
        ).fetchone()

    def _saved(self, owner, plan_id) -> PlanSaveResult:
        plan = _as_plan(self._get(owner, plan_id))
        if plan.execution_date is None:
            return PlanSaveResult(plan, ())
        overlaps = self._db.execute(
            """SELECT id FROM prevention_plans
               WHERE owner_reference = ? AND execution_date = ? AND id <> ?
               AND start_time < ? AND ? < end_time
               ORDER BY start_time, id""",
            (owner, plan.execution_date, plan_id, plan.end_time, plan.start_time),
        ).fetchall()
        return PlanSaveResult(plan, tuple(row["id"] for row in overlaps))

    def save_from_analysis(self, owner_id: str, draft: AnalysisPlanDraft, *, title: str,
                           execution_date: date | str | None = None, start_time: time | str | None = None,
                           end_time: time | str | None = None) -> PlanSaveResult:
        owner = _owner(owner_id)
        if not isinstance(draft, AnalysisPlanDraft):
            raise TypeError("trusted AnalysisPlanDraft required")
        if draft.owner_reference != owner:
            raise PermissionError("analysis is unavailable to this owner")
        if draft.target_type not in TARGET_TYPES or not re.fullmatch(r"[0-9a-f]{32}", draft.analysis_id):
            raise ValueError("invalid analysis draft")
        schedule = _schedule(execution_date, start_time, end_time)
        return self._insert(owner, draft.analysis_id, draft.target_type, title, draft.actions, schedule)

    def create_post(self, owner_id: str, *, title: str, actions: list[str]) -> PlanSaveResult:
        return self._insert(_owner(owner_id), None, "text", title, actions, (None, None, None))

    def _insert(self, owner, analysis_id, target_type, title, actions, schedule) -> PlanSaveResult:
        title = _display_text(title, 120)
        actions = _actions(actions)
        plan_id = uuid4().hex
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            timestamp = _now()
            self._db.execute(
                """INSERT INTO prevention_plans
                   (id, owner_reference, analysis_id, title, target_type, actions,
                    execution_date, start_time, end_time, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (plan_id, owner, analysis_id, title, target_type,
                 json.dumps(actions, ensure_ascii=False), *schedule, timestamp, timestamp),
            )
            return self._saved(owner, plan_id)

    def list_plans(self, owner_id: str) -> list[PreventionPlan]:
        with self._lock:
            rows = self._db.execute(
                """SELECT * FROM prevention_plans WHERE owner_reference = ?
                   ORDER BY execution_date, start_time, id""", (_owner(owner_id),),
            ).fetchall()
        return [_as_plan(row) for row in rows]

    def get_plan(self, owner_id: str, plan_id: str) -> PreventionPlan | None:
        with self._lock:
            row = self._get(_owner(owner_id), plan_id)
        return _as_plan(row) if row is not None else None

    def update_plan(self, owner_id: str, plan_id: str, *, title: str | None = None,
                    actions: list[str] | tuple[str, ...] | None = None,
                    execution_date: date | str | None = None, start_time: time | str | None = None,
                    end_time: time | str | None = None) -> PlanSaveResult | None:
        owner = _owner(owner_id)
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            row = self._get(owner, plan_id)
            if row is None:
                return None
            current = _as_plan(row)
            schedule = _schedule(
                current.execution_date if execution_date is None else execution_date,
                current.start_time if start_time is None else start_time,
                current.end_time if end_time is None else end_time,
            )
            self._db.execute(
                """UPDATE prevention_plans
                   SET title = ?, actions = ?, execution_date = ?, start_time = ?, end_time = ?, updated_at = ?
                   WHERE owner_reference = ? AND id = ?""",
                (current.title if title is None else _display_text(title, 120),
                 json.dumps(current.actions if actions is None else _actions(actions), ensure_ascii=False),
                 *schedule, _now(), owner, plan_id),
            )
            return self._saved(owner, plan_id)

    def delete_plan(self, owner_id: str, plan_id: str) -> bool:
        with self._lock, self._db:
            return self._db.execute(
                "DELETE FROM prevention_plans WHERE owner_reference = ? AND id = ?",
                (_owner(owner_id), plan_id),
            ).rowcount == 1

    def close(self) -> None:
        with self._lock:
            self._db.close()
