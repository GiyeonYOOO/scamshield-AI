from contextlib import closing
from datetime import datetime
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from app.scamshield import ScamshieldAgent
from app.scamshield.events import EventBus, session_reference
from app.scamshield.execution_logs import ExecutionLogs, LoggingAgent
from app.scamshield.llm import DecisionError


URL = "https://example.com/private-path-marker"


def provider(name, url, days=7):
    outcomes = {
        "google": ("NO_MATCH", {"cache_duration": "0s", "matches": []}),
        "vt-url": ("NO_RECORD", None),
        "urlscan": ("NO_CANDIDATES", {"candidates": []}),
    }
    outcome, data = outcomes[name]
    return {"check": name, "ok": outcome != "NO_RECORD", "outcome": outcome, "data": data}


class ExecutionLogTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "events.sqlite"
        self.logs = ExecutionLogs(self.path)
        self.addCleanup(self.logs.close)
        self.bus = EventBus()
        self.bus.subscribe(LoggingAgent(self.logs).record)
        self.agent = ScamshieldAgent(event_bus=self.bus, decider=None, max_replans=1)
        lookup = patch("app.scamshield.tools.providers.run_check", side_effect=provider)
        lookup.start()
        self.addCleanup(lookup.stop)

    def test_normal_run_node_tool_timing_and_replan_events(self):
        result = self.agent.invoke(URL, session_id="session")
        events = self.logs.get_events("session")
        self.assertEqual(events[0]["event_type"], "run.started")
        self.assertEqual(events[-1]["event_type"], "run.finished")
        self.assertEqual(events[-1]["data"], {"status": "completed", "replans": 1})
        self.assertEqual([event["sequence"] for event in events], list(range(1, len(events) + 1)))
        self.assertEqual(len({event["run_id"] for event in events}), 1)
        self.assertTrue(all(datetime.fromisoformat(event["occurred_at"]).utcoffset() is not None
                            for event in events))
        entered = [e["data"]["node"] for e in events if e["event_type"] == "node.entered"]
        finished = [e["data"]["node"] for e in events if e["event_type"] == "node.finished"]
        self.assertEqual(entered, ["analyze", "plan", "execute", "judge", "replan", "execute", "judge", "respond"])
        self.assertEqual(entered, finished)
        requested = [e["data"] for e in events if e["event_type"] == "tool.requested"]
        results = [e["data"] for e in events if e["event_type"] == "tool.finished"]
        self.assertEqual([e["tool"] for e in requested], [e["tool"] for e in results])
        self.assertTrue(all(type(e["duration_ms"]) is int and e["duration_ms"] >= 0 for e in results))
        self.assertEqual([e["outcome"] for e in results], ["NO_MATCH", "NO_RECORD", "NO_CANDIDATES"])
        self.assertIn({"performed": True, "reason": "COVERAGE_INCOMPLETE",
                       "tool": "urlscan_history", "count": 1, "source": "rules"},
                      [e["data"] for e in events if e["event_type"] == "replan.decided"])
        self.assertIn({"code": "NO_RECORD", "handling": "continue"},
                      [e["data"] for e in events if e["event_type"] == "error.handled"])
        self.assertEqual([e["data"] for e in events if e["event_type"] == "response.generated"],
                         [{"status": result["status"]}])

    def test_llm_reason_is_recorded_only_when_explicit(self):
        model = Mock()
        model.choose.side_effect = [
            [("google_safe_browsing", {"reason_code": "known_threat_lookup"})],
            [("prioritize_action", {"index": 0, "evidence_index": 0})],
        ]
        agent = ScamshieldAgent(event_bus=self.bus, decider=model)
        agent.invoke(URL, session_id="llm")
        decisions = [e["data"] for e in self.logs.get_events("llm") if e["event_type"] == "llm.decision"]
        self.assertEqual(decisions, [
            {"stage": "intent_and_plan", "choice": "google_safe_browsing", "reason": "known_threat_lookup"},
            {"stage": "response", "choice": "prioritize_action"},
        ])

    def test_llm_failure_logs_only_safe_error_and_falls_back(self):
        model = Mock()
        model.choose.side_effect = DecisionError("LLM_AUTH_ERROR")
        agent = ScamshieldAgent(event_bus=self.bus, decider=model, max_replans=0)
        self.assertEqual(agent.invoke(URL, session_id="llm-error")["llm_error"], "LLM_AUTH_ERROR")
        errors = [e["data"] for e in self.logs.get_events("llm-error") if e["event_type"] == "error.handled"]
        self.assertIn({"code": "LLM_AUTH_ERROR", "handling": "rules_fallback"}, errors)
        model.choose.assert_called_once()

    def test_sessions_list_detail_delete_and_reopen(self):
        self.agent.invoke("안녕하세요", session_id="first")
        self.agent.invoke("안녕하세요", session_id="second")
        self.agent.invoke("안녕하세요", session_id="first")
        first = self.logs.list_runs("first")
        second = self.logs.list_runs("second")
        self.assertEqual((len(first), len(second)), (2, 1))
        self.assertEqual(self.logs.get_events("first", run_id=second[0]["run_id"]), [])
        self.assertEqual(self.logs.delete("first", run_id=first[0]["run_id"]), first[0]["event_count"])
        reopened = ExecutionLogs(self.path)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.list_runs("first"), first[1:])
        self.assertEqual(reopened.delete("first"), first[1]["event_count"])
        self.assertEqual(self.logs.get_events("first"), [])
        self.assertEqual(self.logs.list_runs("second"), second)

    def test_update_rejected_by_sqlite(self):
        self.agent.invoke("안녕하세요", session_id="immutable")
        with closing(sqlite3.connect(self.path)) as db, self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE execution_events SET event_type = 'changed'")
        self.assertEqual(self.logs.get_events("immutable")[0]["event_type"], "run.started")

    def test_response_without_logging_subscriber(self):
        agent = ScamshieldAgent(decider=None)
        self.assertEqual(agent.invoke("안녕하세요", session_id="none")["status"], "GENERAL")

    def test_deleting_active_run_does_not_restore_it_on_subsequent_events(self):
        deleted = []

        def remove_started_run(event):
            if event.event_type == "run.started":
                deleted.append(self.logs.delete("active", run_id=event.run_id))

        self.bus.subscribe(remove_started_run)
        self.agent.invoke("안녕하세요", session_id="active")
        self.assertEqual(deleted, [1])
        self.assertEqual(self.logs.get_events("active"), [])

    def test_sqlite_save_failure_does_not_break_response_or_other_subscribers(self):
        broken = ExecutionLogs(":memory:")
        broken.close()
        bus = EventBus()
        bus.subscribe(LoggingAgent(broken).record)
        bus.subscribe(LoggingAgent(self.logs).record)
        agent = ScamshieldAgent(event_bus=bus, decider=None)
        self.assertEqual(agent.invoke("안녕하세요", session_id="saved")["status"], "GENERAL")
        self.assertEqual(self.logs.get_events("saved")[-1]["event_type"], "run.finished")

    def test_sensitive_content_is_not_in_saved_event_data(self):
        sensitive_session = "jane.private@example.com"
        secret = "sensitive-api-token-marker"
        self.agent.invoke(f"{URL} 사용자 정보 {secret}", session_id=sensitive_session)
        events = self.logs.get_events(sensitive_session)
        self.assertTrue(events)
        serialized = json.dumps(events)
        for raw in (sensitive_session, URL, secret, "private-path-marker"):
            self.assertNotIn(raw, serialized)
        self.assertEqual(events[0]["session_id"], session_reference(sensitive_session))

    def test_unexpected_tool_error_closes_node_and_run_without_logging_raw_exception(self):
        with patch("app.scamshield.tools.providers.run_check", side_effect=RuntimeError("secret details")):
            with self.assertRaises(RuntimeError):
                self.agent.invoke(URL, session_id="failed")
        events = self.logs.get_events("failed")
        self.assertEqual(events[-1]["data"]["status"], "failed")
        self.assertIn({"node": "execute", "status": "failed"},
                      [e["data"] for e in events if e["event_type"] == "node.finished"])
        self.assertNotIn("secret details", json.dumps(events))
