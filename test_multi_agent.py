from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.scamshield.events import EventBus, RunEvents
from app.scamshield.execution_logs import ExecutionLogs, LoggingAgent
from app.scamshield.planner import PlannerAgent
from app.scamshield.work import PlanBatch, Task, ToolArguments, WorkerAgent, WorkResult
from app.scamshield_api import create_app


URL = "https://example.com/"
NOW = datetime(2026, 11, 18, 9, tzinfo=timezone.utc)


def outcome(code, data=None):
    return {"check": "test", "ok": code in {"NO_MATCH", "REPORT", "CANDIDATES", "NO_CANDIDATES"},
            "outcome": code, "data": data}


class MultiAgentTests(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.events = []
        self.bus.subscribe(self.events.append)
        self.model = Mock()
        self.agent = PlannerAgent(decider=self.model, clock=lambda: NOW, event_bus=self.bus)
        provider = patch("app.scamshield.tools.providers.run_check", side_effect=self.lookup)
        self.provider = provider.start()
        self.addCleanup(provider.stop)

    @staticmethod
    def lookup(name, url, days=7):
        if name == "google":
            return outcome("NO_MATCH", {"matches": [], "cache_duration": "300s"})
        if name == "vt-url":
            return outcome("REPORT", {"last_analysis_date": int(NOW.timestamp()), "last_analysis_stats": {}})
        if days == 7:
            return outcome("NO_CANDIDATES", {"candidates": []})
        return outcome("CANDIDATES", {"candidates": [{
            "scope": "exact_url", "scan_id": "safe-id", "observed_at": NOW.isoformat(),
        }]})

    def _data(self, kind):
        return [dict(event.data) for event in self.events if event.event_type == kind]

    def test_success_has_plan_worker_and_verification_and_no_worker_llm(self):
        self.model.choose.side_effect = [
            [("google_safe_browsing", {})], [("prioritize_action", {"index": 0, "evidence_index": 0})],
        ]
        result = self.agent.invoke(URL, session_id="normal")
        self.assertEqual(result["status"], "NO_KNOWN_MATCH")
        self.assertEqual(self._data("planner.task")[0]["tool"], "google_safe_browsing")
        self.assertFalse(self._data("worker.decision")[0]["llm_called"])
        self.assertEqual(self._data("audit.checked")[0]["status"], "verified")
        self.assertEqual(self.model.choose.call_count, 2)

    def test_adjustable_failure_retries_same_tool_once_with_fixed_url(self):
        self.model.choose.side_effect = [
            [("urlscan_history", {})], [("retry_same_tool", {})],
            [("prioritize_action", {"index": 0, "evidence_index": 0})],
        ]
        result = self.agent.invoke(URL, session_id="retry")
        self.assertEqual(self.provider.call_args_list[0].args, ("urlscan", URL, 7))
        self.assertEqual(self.provider.call_args_list[1].args, ("urlscan", URL, 14))
        self.assertEqual(result["replans"], 0)
        self.assertTrue(self._data("worker.decision")[0]["retried"])

    def test_exhausted_retry_is_forwarded_and_planner_changes_tool(self):
        original = self.lookup
        self.provider.side_effect = lambda name, *args: (
            outcome("NO_CANDIDATES", {"candidates": []}) if name == "urlscan" else original(name, *args)
        )
        self.model.choose.side_effect = [
            [("urlscan_history", {})], [("retry_same_tool", {})], [("virustotal_url", {})],
            [("prioritize_action", {"index": 0, "evidence_index": 1})],
        ]
        result = self.agent.invoke(URL, session_id="exhausted")
        self.assertEqual(result["replans"], 1)
        self.assertEqual([c.args[0] for c in self.provider.call_args_list], ["urlscan", "urlscan", "vt-url"])
        self.assertTrue(self._data("worker.decision")[0]["request_plan_change"])
        self.assertIn("WORKER_REQUESTED_CHANGE", [e["reason"] for e in self._data("replan.decided")])

    def test_user_period_and_auth_failure_do_not_invoke_worker_llm(self):
        for code in ("NO_CANDIDATES", "AUTH_ERROR", "MISSING_KEY"):
            with self.subTest(code=code):
                self.provider.reset_mock()
                self.model.choose.reset_mock()
                self.provider.return_value = outcome(code)
                self.provider.side_effect = None
                self.model.choose.side_effect = [[("urlscan_history", {})]]
                result = self.agent.invoke(
                    f"{URL} 최근 24시간 이내 기록, urlscan.io만 조회", session_id=code,
                )
                self.assertEqual(self.provider.call_args.args, ("urlscan", URL, 1))
                self.provider.assert_called_once()
                self.model.choose.assert_called_once()
                self.assertFalse(self._data("worker.decision")[-1]["llm_called"])
                self.assertEqual(result["replans"], 0)

    def test_missing_argument_yields_failure_without_tool_or_model_call(self):
        run = RunEvents(self.bus, "demo")
        task = Task(run.run_id, 1, "urlscan_history", ToolArguments("", 7), frozenset({"url"}), ())
        tool = Mock()
        result, = WorkerAgent().execute(PlanBatch(run.run_id, 0, (task,)), tool, run, self.model)
        self.assertEqual(result.failure_code, "INVALID_INPUT")
        self.assertTrue(result.request_plan_change)
        tool.assert_not_called()
        self.model.choose.assert_not_called()

    def test_unplanned_actual_call_is_rejected_and_causes_new_plan(self):
        normal = self.agent.worker.execute
        def unexpected(plan, invoke_tool, run, decider):
            if plan.revision == 0:
                invoke_tool("virustotal_url", {"url": URL}, run)
            return normal(plan, invoke_tool, run, decider)
        self.agent.worker.execute = unexpected
        self.provider.side_effect = lambda name, url, days=7: self.lookup(
            name, url, 14 if name == "urlscan" else days,
        )
        self.model.choose.side_effect = [
            [("google_safe_browsing", {})], [("urlscan_history", {})],
            [("prioritize_action", {"index": 0, "evidence_index": 0})],
        ]
        result = self.agent.invoke(URL, session_id="anomaly")
        self.assertEqual(result["replans"], 1)
        self.assertNotIn("virustotal_url", result["tool_outcomes"])
        self.assertIn("UNPLANNED_TOOL", [e.get("code") for e in self._data("audit.checked")])
        self.assertIn("AUDIT_ANOMALY", [e.get("reason") for e in self._data("replan.decided")])

    def test_verifier_detects_duplicate_fixed_argument_changes_and_limits(self):
        run = RunEvents(self.bus, "demo")
        task = Task(run.run_id, 1, "urlscan_history", ToolArguments(URL, 1),
                    frozenset({"url", "days"}), (("max_age_hours", 24),))
        plan = PlanBatch(run.run_id, 3, (task,))
        attempt = WorkerAgent._attempt(task, replace(task.arguments, days=2), 1, self.agent._call_tool, run)
        work = (WorkResult(task, (attempt, attempt, attempt), "NO_CANDIDATES", True),)
        checked = LoggingAgent(None).verify(plan, work, run.audit_events, set(), 2, run, self.model)
        self.assertEqual(checked.status, "anomaly")
        self.assertTrue({"DUPLICATE_CALL", "FIXED_ARGUMENT_CHANGED", "RETRY_LIMIT", "REPLAN_LIMIT"}
                        <= set(checked.codes))
        self.model.choose.assert_not_called()

    def test_audit_llm_is_reserved_for_partial_provider_report(self):
        self.provider.side_effect = lambda name, *args: (
            outcome("INCOMPLETE_REPORT", {"last_analysis_stats": {"malicious": 0}})
            if name == "vt-url" else self.lookup(name, *args)
        )
        self.model.choose.side_effect = [
            [("virustotal_url", {})], [("keep_for_manual_review", {})], [("finish_without_lookup", {})],
        ]
        self.agent.invoke(URL, session_id="audit-review")
        review = self._data("audit.checked")[0]
        self.assertEqual(review["status"], "needs_review")
        self.assertTrue(review["llm_called"])
        self.assertEqual(self.model.choose.call_args_list[1].args[0], "log_review")

    def test_worker_disabled_routes_recoverable_failure_to_planner(self):
        agent = PlannerAgent(decider=self.model, clock=lambda: NOW, event_bus=self.bus,
                             enable_worker_llm=False)
        self.model.choose.side_effect = [
            [("urlscan_history", {})], [("virustotal_url", {})],
            [("prioritize_action", {"index": 0, "evidence_index": 1})],
        ]
        result = agent.invoke(URL, session_id="disabled")
        self.assertEqual(result["replans"], 1)
        self.assertEqual([c.args[0] for c in self.provider.call_args_list], ["urlscan", "vt-url"])
        self.assertFalse(any(d["llm_called"] for d in self._data("worker.decision")))
        self.assertTrue(self._data("worker.decision")[0]["request_plan_change"])

    def test_api_and_website_with_planner_and_saved_event_messages(self):
        with TemporaryDirectory() as folder:
            app = create_app(db_path=Path(folder) / "multi.sqlite")
            with patch.dict("os.environ", {"SCAMSHIELD_AGENT_MODE": "multi"}), patch(
                "app.scamshield.llm.OpenAICompatibleDecider.from_env", return_value=None,
            ), TestClient(app, base_url="https://testserver") as client:
                self.assertEqual(client.get("/").status_code, 200)
                chat = client.post("/api/chat", json={"message": URL})
                self.assertEqual(chat.status_code, 200)
                data = chat.json()
                self.assertTrue(data["plan_draft"])
                log = client.get(f"/api/logs/{data['run_id']}").json()["events"]
                self.assertTrue({"planner.task", "worker.attempt", "worker.decision", "audit.checked"}
                                <= {event["event_type"] for event in log})
                self.assertNotIn(URL, str(log))
