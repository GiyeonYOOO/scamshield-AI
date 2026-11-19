from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.scamshield.events import EventBus, RunEvents, session_reference
from app.scamshield.execution_logs import ExecutionLogs, LoggingAgent
from app.scamshield.llm import DecisionError
from app.scamshield_api import create_app


URL = "https://example.com/private-input"


class LogEvaluationTests(TestCase):
    def setUp(self):
        self.logs = ExecutionLogs(":memory:")
        self.addCleanup(self.logs.close)
        self.logger = LoggingAgent(self.logs)
        self.model = Mock()
        self.model.choose.return_value = [
            ("diagnose_warning", {"component": "Worker", "evidence_code": "DUPLICATE_CALL"}),
        ]
        self.bus = EventBus()
        self.bus.subscribe(self.logger.record)
        self.run_log = RunEvents(self.bus, session_reference("owner"))

    def _plan(self, *, cap=2, fixed=True):
        self.run_log.emit("run.started", max_replans=cap)
        self.run_log.emit("planner.task", task_id=1, tool="urlscan_history", revision=0,
                          fixed_url=True, fixed_days=fixed, days=7, input_url=URL)

    def _attempt(self, *, url=URL, days=7, tool="urlscan_history", number=1):
        self.run_log.emit("worker.attempt", task_id=1, tool=tool, days=days, attempt=number)
        self.run_log.emit("tool.requested", tool=tool, days=days, input_url=url)
        self.run_log.emit("tool.finished", tool=tool, outcome="NO_CANDIDATES", ok=True, duration_ms=1)

    def _finish(self, *, audit="verified", code=None):
        self.run_log.emit("audit.checked", status=audit, code=code, revision=0)
        self.run_log.emit("response.generated", status="INSUFFICIENT_EVIDENCE")
        self.run_log.emit("run.finished", status="completed", replans=0)

    def _evaluate(self, decider=None):
        return self.logger.evaluate("owner", self.run_log.run_id, decider)

    def test_normal_and_allowed_retry_do_not_diagnose(self):
        self._plan(fixed=False)
        self._attempt()
        self._attempt(days=14, number=2)
        self._finish()
        result = self._evaluate(self.model)
        self.assertEqual(result["status"], "normal")
        self.assertEqual(result["warnings"], [])
        self.assertIsNone(result["diagnosis"])
        self.model.choose.assert_not_called()

    def test_duplicate_is_diagnosed_once_and_original_events_are_unchanged(self):
        self._plan()
        self._attempt()
        self._attempt(number=2)
        self._finish(audit="anomaly", code="DUPLICATE_CALL")
        before = self.logs.get_events("owner", run_id=self.run_log.run_id)
        result = self._evaluate(self.model)
        self.assertEqual(result, self._evaluate(self.model))
        self.model.choose.assert_called_once()
        self.assertEqual(result["status"], "warning")
        self.assertEqual(len(result["warnings"]), 1)
        warning, = result["warnings"]
        self.assertGreaterEqual(len(warning["evidence_event_ids"]), 2)
        self.assertTrue(all(value.startswith(f"{self.run_log.run_id}:") for value in warning["evidence_event_ids"]))
        self.assertEqual(result["diagnosis"]["status"], "completed")
        self.assertEqual(result["diagnosis"]["text"].count("."), 3)
        self.assertEqual(before, self.logs.get_events("owner", run_id=self.run_log.run_id))
        self.assertNotIn(URL, str(before))
        self.assertNotIn(URL, str(self.model.choose.call_args))

    def test_detects_fixed_url_period_and_unplanned_tool(self):
        self._plan()
        self._attempt(url="https://example.org/", days=14)
        self._attempt(tool="virustotal_url")
        self._finish()
        result = self._evaluate()
        self.assertEqual({item["code"] for item in result["warnings"]},
                         {"FIXED_ARGUMENT_CHANGED", "UNPLANNED_TOOL"})

    def test_replan_limit_and_live_result_check_are_reused(self):
        self._plan(cap=1)
        self._attempt()
        self.run_log.emit("replan.decided", performed=True, count=1)
        self.run_log.emit("replan.decided", performed=True, count=2)
        self._finish(audit="anomaly", code="MISSING_OR_EXTRA_ATTEMPT")
        result = self._evaluate()
        self.assertEqual({item["code"] for item in result["warnings"]},
                         {"REPLAN_LIMIT", "MISSING_OR_EXTRA_ATTEMPT"})

    def test_insufficient_events_are_persisted_and_update_when_run_finishes(self):
        self._plan()
        early = self._evaluate(self.model)
        self.assertEqual(early["status"], "inconclusive")
        self.assertEqual(early["reason"], "INSUFFICIENT_EVENTS")
        self.assertEqual(self.logs.get_evaluation("owner", self.run_log.run_id), early)
        self._attempt()
        self._finish()
        self.assertEqual(self._evaluate(self.model)["status"], "normal")
        self.model.choose.assert_not_called()

    def test_diagnosis_failure_preserves_warnings_and_is_not_retried(self):
        self.model.choose.side_effect = DecisionError("LLM_TIMEOUT")
        self._plan()
        self._attempt()
        self._attempt(number=2)
        self._finish()
        result = self._evaluate(self.model)
        self.assertEqual(result["diagnosis"], {"status": "failed", "error_code": "LLM_TIMEOUT"})
        self.assertEqual(result["warnings"][0]["code"], "DUPLICATE_CALL")
        self.assertTrue(self.logs.get_events("owner"))
        self._evaluate(self.model)
        self.model.choose.assert_called_once()

    def test_concurrent_evaluation_claims_one_diagnosis_and_delete_clears_results(self):
        self._plan()
        self._attempt()
        self._attempt(number=2)
        self._finish()
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(self._evaluate, [self.model, self.model]))
        self.model.choose.assert_called_once()
        self.assertIsNone(self.logs.get_evaluation("different-owner", self.run_log.run_id))
        self.assertTrue(self.logs.delete("owner", run_id=self.run_log.run_id))
        self.assertIsNone(self.logs.get_evaluation("owner", self.run_log.run_id))

    def test_api_reads_automatic_evaluation_with_session_scope(self):
        with TemporaryDirectory() as folder:
            app = create_app(db_path=Path(folder) / "evaluation.sqlite")
            with patch.dict("os.environ", {"SCAMSHIELD_AGENT_MODE": "multi"}), patch(
                "app.scamshield.llm.OpenAICompatibleDecider.from_env", return_value=None,
            ), TestClient(app, base_url="https://testserver") as client:
                run_id = client.post("/api/chat", json={"message": "안녕하세요"}).json()["run_id"]
                endpoint = f"/api/logs/{run_id}/evaluation"
                response = client.get(endpoint)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["status"], "normal")
                with_other_cookie = TestClient(app, base_url="https://testserver")
                self.addCleanup(with_other_cookie.close)
                self.assertEqual(with_other_cookie.post("/api/chat", json={"message": "안녕하세요"}).status_code, 200)
                self.assertEqual(with_other_cookie.get(endpoint).status_code, 404)
                self.assertEqual(client.delete(f"/api/logs/{run_id}").status_code, 204)
                self.assertEqual(client.get(endpoint).status_code, 404)
