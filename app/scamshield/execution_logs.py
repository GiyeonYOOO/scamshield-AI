"""F3013/F3014: SQLite event storage, subscriber, and log queries."""

import json
from pathlib import Path
import sqlite3
from threading import Lock

from .events import OUTCOMES, ExecutionEvent, session_reference
from .execution_audit import verify_execution
from .llm import DecisionError
from .log_evaluation import diagnose, evaluate_events


SCHEMA = """
CREATE TABLE IF NOT EXISTS execution_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    data TEXT NOT NULL,
    UNIQUE (run_id, sequence)
);
CREATE INDEX IF NOT EXISTS execution_events_session ON execution_events(session_id, id);
CREATE TABLE IF NOT EXISTS deleted_active_runs (
    run_id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS execution_evaluations (
    session_id TEXT NOT NULL, run_id TEXT NOT NULL,
    last_sequence INTEGER NOT NULL, event_count INTEGER NOT NULL, result TEXT NOT NULL,
    PRIMARY KEY (session_id, run_id)
);
CREATE TABLE IF NOT EXISTS execution_diagnoses (
    session_id TEXT NOT NULL, run_id TEXT NOT NULL,
    status TEXT NOT NULL, result TEXT,
    PRIMARY KEY (session_id, run_id)
);
CREATE TRIGGER IF NOT EXISTS execution_events_no_update
BEFORE UPDATE ON execution_events
BEGIN
    SELECT RAISE(ABORT, 'execution events are immutable');
END;
"""


class ExecutionLogs:
    """Append-only event store with session and run queries and deletion."""

    def __init__(self, path: str | Path):
        self._lock = Lock()
        self._db = sqlite3.connect(path, timeout=0.25, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        try:
            self._db.executescript(SCHEMA)
        except sqlite3.Error:
            self._db.close()
            raise

    def append(self, event: ExecutionEvent) -> None:
        with self._lock, self._db:
            self._db.execute(
                """INSERT INTO execution_events
                   (session_id, run_id, sequence, occurred_at, event_type, data)
                   SELECT ?, ?, ?, ?, ?, ?
                   WHERE NOT EXISTS (SELECT 1 FROM deleted_active_runs WHERE run_id = ?)
                   ON CONFLICT(run_id, sequence) DO NOTHING""",
                (event.session_id, event.run_id, event.sequence, event.occurred_at,
                 event.event_type, json.dumps(dict(event.data), ensure_ascii=False), event.run_id),
            )
            if event.event_type == "run.finished":
                self._db.execute("DELETE FROM deleted_active_runs WHERE run_id = ?", (event.run_id,))

    def list_runs(self, session_id: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                """SELECT run_id, MIN(occurred_at) AS started_at,
                          MAX(CASE WHEN event_type = 'run.finished' THEN occurred_at END) AS ended_at,
                          COUNT(*) AS event_count
                   FROM execution_events WHERE session_id = ?
                   GROUP BY run_id ORDER BY MIN(id)""",
                (session_reference(session_id),),
            ).fetchall()
        return [dict(row) for row in rows]

    def _session_filter(self, session_id, run_id):
        if run_id is None:
            return "session_id = ?", (session_reference(session_id),)
        return "session_id = ? AND run_id = ?", (session_reference(session_id), run_id)

    def get_events(self, session_id: str, *, run_id: str | None = None) -> list[dict]:
        where, parameters = self._session_filter(session_id, run_id)
        order = "id" if run_id is None else "sequence"
        with self._lock:
            rows = self._db.execute(
                f"""SELECT session_id, run_id, sequence, occurred_at, event_type, data
                    FROM execution_events WHERE {where} ORDER BY {order}""",
                parameters,
            ).fetchall()
        return [{**dict(row), "data": json.loads(row["data"])} for row in rows]

    def evaluation_events(self, reference, run_id):
        with self._lock:
            rows = self._db.execute(
                """SELECT sequence, event_type, data FROM execution_events
                   WHERE session_id = ? AND run_id = ? ORDER BY sequence""",
                (reference, run_id),
            ).fetchall()
        return [{**dict(row), "data": json.loads(row["data"])} for row in rows]

    def save_evaluation(self, reference, run_id, events, result, *, diagnose_warning=False):
        """Save the reviewed snapshot and claim at most one diagnosis per run."""
        key = (reference, run_id)
        sequence = events[-1]["sequence"]
        count = len(events)
        with self._lock, self._db:
            self._db.execute("BEGIN IMMEDIATE")
            actual = self._db.execute(
                """SELECT MAX(sequence), COUNT(*) FROM execution_events
                   WHERE session_id = ? AND run_id = ?""", key,
            ).fetchone()
            if tuple(actual) != (sequence, count):
                return False
            self._db.execute(
                """INSERT INTO execution_evaluations VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(session_id, run_id) DO UPDATE SET
                   last_sequence = excluded.last_sequence, event_count = excluded.event_count,
                   result = excluded.result
                   WHERE execution_evaluations.last_sequence != excluded.last_sequence
                   OR execution_evaluations.event_count != excluded.event_count""",
                (*key, sequence, count, json.dumps(result, ensure_ascii=False)),
            )
            if diagnose_warning:
                return self._db.execute(
                    """INSERT INTO execution_diagnoses VALUES (?, ?, 'pending', NULL)
                       ON CONFLICT(session_id, run_id) DO NOTHING""", key,
                ).rowcount == 1
        return False

    def finish_diagnosis(self, reference, run_id, status, result):
        with self._lock, self._db:
            self._db.execute(
                """UPDATE execution_diagnoses SET status = ?, result = ?
                   WHERE session_id = ? AND run_id = ? AND status = 'pending'""",
                (status, json.dumps(result, ensure_ascii=False), reference, run_id),
            )

    def get_evaluation(self, session_id: str, run_id: str) -> dict | None:
        return self.evaluation_by_reference(session_reference(session_id), run_id)

    def evaluation_by_reference(self, reference, run_id):
        with self._lock:
            row = self._db.execute(
                """SELECT e.result, d.status AS diagnosis_status, d.result AS diagnosis_result
                   FROM execution_evaluations e LEFT JOIN execution_diagnoses d USING(session_id, run_id)
                   WHERE e.session_id = ? AND e.run_id = ?""",
                (reference, run_id),
            ).fetchone()
        if row is None:
            return None
        diagnosis = None
        if row["diagnosis_status"]:
            diagnosis = {"status": row["diagnosis_status"],
                         **(json.loads(row["diagnosis_result"]) if row["diagnosis_result"] else {})}
        return {"run_id": run_id, **json.loads(row["result"]), "diagnosis": diagnosis}

    def delete(self, session_id: str, *, run_id: str | None = None) -> int:
        where, parameters = self._session_filter(session_id, run_id)
        with self._lock, self._db:
            self._db.execute(f"DELETE FROM execution_diagnoses WHERE {where}", parameters)
            self._db.execute(f"DELETE FROM execution_evaluations WHERE {where}", parameters)
            self._db.execute(
                f"""INSERT OR IGNORE INTO deleted_active_runs(run_id)
                    SELECT run_id FROM execution_events WHERE {where} GROUP BY run_id
                    HAVING MAX(event_type = 'run.finished') = 0""",
                parameters,
            )
            return self._db.execute(f"DELETE FROM execution_events WHERE {where}", parameters).rowcount

    def close(self) -> None:
        with self._lock:
            self._db.close()


class LoggingAgent:
    """Record original events directly and evaluate completed runs separately."""

    def __init__(self, logs: ExecutionLogs):
        self.logs = logs

    def record(self, event: ExecutionEvent) -> None:
        self.logs.append(event)

    def verify(self, plan, work, events, previous_calls, max_replans, run, decider=None):
        return verify_execution(plan, work, events, previous_calls, max_replans, run, decider)

    def evaluate(self, session_id, run_id, decider=None):
        return self._evaluate(session_reference(session_id), run_id, decider)

    def evaluate_completed(self, event, decider=None):
        if event.event_type == "run.finished":
            self._evaluate(event.session_id, event.run_id, decider)

    def _evaluate(self, reference, run_id, decider):
        events = self.logs.evaluation_events(reference, run_id)
        if not events:
            return None
        result = evaluate_events(events, run_id)
        claim = self.logs.save_evaluation(
            reference, run_id, events, result,
            diagnose_warning=bool(
                decider and result["warnings"] and events[-1]["event_type"] == "run.finished"
            ),
        )
        if claim:
            try:
                diagnosis = diagnose(decider, result["warnings"])
            except DecisionError as error:
                code = str(error)
                self.logs.finish_diagnosis(reference, run_id, "failed",
                                           {"error_code": code if code in OUTCOMES else "LLM_REJECTED_CHOICE"})
            except Exception:
                self.logs.finish_diagnosis(reference, run_id, "failed", {"error_code": "LLM_INVALID_RESPONSE"})
            else:
                self.logs.finish_diagnosis(reference, run_id, "completed", diagnosis)
        return self.logs.evaluation_by_reference(reference, run_id)
