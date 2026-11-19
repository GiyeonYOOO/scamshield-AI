from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.scamshield import ScamshieldAgent
from app.scamshield_api import COOKIE_NAME, create_app


URL = "https://example.com/"
NOW = datetime(2026, 11, 18, 9, tzinfo=timezone.utc)


def provider(check, url, days=7):
    defaults = {
        "google": ("NO_MATCH", {"cache_duration": "300s", "matches": []}),
        "vt-url": ("REPORT", {"last_analysis_date": int(NOW.timestamp()),
                              "last_analysis_stats": {"malicious": 0}}),
    }
    outcome, data = defaults[check]
    return {"check": check, "outcome": outcome, "data": data, "ok": True}


class ScamshieldApiTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "api.sqlite"
        mock = patch("app.scamshield.tools.providers.run_check", side_effect=provider)
        self.provider = mock.start()
        self.addCleanup(mock.stop)
        self.created_agents = []
        self.client = self.new_client()

    def new_client(self):
        application = create_app(db_path=self.path, agent_factory=self.create_agent)
        client = TestClient(application, base_url="https://testserver")
        self.addCleanup(client.__exit__, None, None, None)
        return client.__enter__()

    def create_agent(self, **kwargs):
        agent = ScamshieldAgent(decider=None, clock=lambda: NOW, max_replans=0, **kwargs)
        self.created_agents.append(agent)
        return agent

    def analyze(self, client=None, message=URL):
        client = client or self.client
        result = client.post("/api/chat", json={"message": message})
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def plan_body(self, analysis_id, **updates):
        return {"analysis_id": analysis_id, "title": "공식 번호로 확인",
                "execution_date": "2026-11-18", "start_time": "09:00", "end_time": "10:00",
                **updates}

    def test_chat_draft_log_id_and_session_continuity(self):
        first = self.client.post("/api/chat", json={"message": URL})
        self.assertEqual(first.status_code, 200)
        self.assertIn("HttpOnly", first.headers["set-cookie"])
        self.assertIn("SameSite=strict", first.headers["set-cookie"])
        self.assertIn("Secure", first.headers["set-cookie"])
        self.assertEqual(first.headers["cache-control"], "no-store")
        result = first.json()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["analysis"]["status"], "NO_KNOWN_MATCH")
        self.assertTrue(result["analysis"]["evidence"])
        self.assertEqual(result["run_id"], result["plan_draft"]["analysis_id"])
        follow_up = self.analyze(message="같은 링크인데 최근 24시간 이내 기록만 확인해 주세요.")
        self.assertNotEqual(follow_up["run_id"], result["run_id"])
        self.assertEqual(follow_up["analysis"]["conditions"], {"max_age_hours": 24})
        self.assertEqual(self.provider.call_args.args[1], URL)
        self.assertEqual(len(self.created_agents), 1)
        self.assertEqual(self.client.get("/api/plans").json(), [])

    def test_plan_crud_overlap_and_validation(self):
        analysis_id = self.analyze()["run_id"]
        a = self.client.post("/api/plans", json=self.plan_body(analysis_id))
        b = self.client.post("/api/plans", json=self.plan_body(analysis_id, start_time="09:30"))
        self.assertEqual((a.status_code, b.status_code), (201, 201))
        first, second = a.json()["plan"]["id"], b.json()["plan"]["id"]
        self.assertEqual(b.json()["overlapping_plan_ids"], [first])
        self.assertEqual(len(self.client.get("/api/plans").json()), 2)
        self.assertEqual(self.client.get(f"/api/plans/{second}").json()["id"], second)
        changed = self.client.patch(f"/api/plans/{second}", json={"start_time": "10:00", "end_time": "11:00"})
        self.assertEqual(changed.status_code, 200)
        self.assertFalse(changed.json()["has_overlap"])
        bad = self.client.patch(f"/api/plans/{second}", json={"end_time": "09:00"})
        self.assertEqual(bad.json()["error"]["code"], "INVALID_SCHEDULE")
        self.assertEqual(self.client.delete(f"/api/plans/{second}").status_code, 204)
        self.assertEqual(self.client.get(f"/api/plans/{second}").status_code, 404)

    def test_log_list_detail_delete_and_no_update_routes(self):
        run_id = self.analyze()["run_id"]
        logs = self.client.get("/api/logs").json()
        self.assertEqual([run["run_id"] for run in logs], [run_id])
        endpoint = f"/api/logs/{run_id}"
        detail = self.client.get(endpoint).json()
        self.assertEqual(detail["events"][0]["event_type"], "run.started")
        self.assertEqual([i["sequence"] for i in detail["events"]], list(range(1, len(detail["events"]) + 1)))
        self.assertNotIn("session_id", detail["events"][0])
        self.assertEqual(self.client.patch(endpoint, json={}).status_code, 405)
        self.assertEqual(self.client.put(endpoint, json={}).status_code, 405)
        self.assertEqual(self.client.delete(endpoint).status_code, 204)
        self.assertEqual(self.client.get(endpoint).status_code, 404)

    def test_other_session_cannot_read_or_modify_data_or_save_draft(self):
        run_id = self.analyze()["run_id"]
        plan_id = self.client.post("/api/plans", json=self.plan_body(run_id)).json()["plan"]["id"]
        other = self.new_client()
        self.assertEqual(other.get("/api/plans").status_code, 401)
        self.analyze(other, message="안녕하세요")
        self.assertEqual(other.get("/api/plans").json(), [])
        self.assertEqual(other.post("/api/plans", json=self.plan_body(run_id)).status_code, 404)
        for method, endpoint, kwargs in (
            ("GET", f"/api/plans/{plan_id}", {}),
            ("PATCH", f"/api/plans/{plan_id}", {"json": {"title": "다른 세션"}}),
            ("DELETE", f"/api/plans/{plan_id}", {}),
            ("GET", f"/api/logs/{run_id}", {}),
            ("DELETE", f"/api/logs/{run_id}", {}),
        ):
            with self.subTest(method=method, endpoint=endpoint):
                self.assertEqual(other.request(method, endpoint, **kwargs).status_code, 404)
        self.assertEqual(self.client.get(f"/api/plans/{plan_id}").status_code, 200)
        self.assertEqual(self.client.get(f"/api/logs/{run_id}").status_code, 200)

    def test_invalid_input_rejected_without_sensitive_error_echo(self):
        r = self.client.post("/api/chat", json={"message": URL, "owner_id": "injected-secret"})
        self.assertEqual(r.status_code, 422)
        self.assertNotIn("injected-secret", r.text)
        for message in ("http://", "http:/example.com", "ftp://example.com/", f"{URL}?token=private"):
            with self.subTest(message=message):
                r = self.client.post("/api/chat", json={"message": message})
                self.assertEqual(r.status_code, 422)
                self.assertEqual(r.json()["error"]["code"], "INVALID_URL")
        run_id = self.analyze()["run_id"]
        bad_plan = self.client.post("/api/plans", json=self.plan_body(run_id, execution_date="2026-02-30"))
        self.assertEqual(bad_plan.status_code, 422)
        self.assertEqual(self.client.get("/api/plans").json(), [])

    def test_unauthenticated_and_forged_cookies_and_cross_origin_requests(self):
        self.assertEqual(self.client.get("/api/logs?session_id=anything").status_code, 401)
        self.client.cookies.set(COOKIE_NAME, "a" * 43)
        self.assertEqual(self.client.post("/api/chat", json={"message": URL}).status_code, 401)
        self.client.cookies.clear()
        response = self.client.post("/api/chat", json={"message": URL}, headers={"Origin": "https://other.test"})
        self.assertEqual(response.status_code, 403)
        self.provider.assert_not_called()

    def test_provider_failure_returns_partial_and_unexpected_error_is_sanitized(self):
        self.provider.side_effect = [
            {"ok": False, "outcome": "NETWORK_ERROR", "data": None},
            provider("vt-url", URL),
        ]
        result = self.analyze()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["analysis"]["tool_errors"], {"google_safe_browsing": "NETWORK_ERROR"})
        self.assertEqual(result["analysis"]["evidence"][0]["exclusion_reasons"][0]["code"], "API_ERROR")
        self.provider.side_effect = RuntimeError("private-key-error-value")
        error = self.client.post("/api/chat", json={"message": "https://example.org/"})
        self.assertEqual(error.status_code, 500)
        self.assertNotIn("private-key-error-value", error.text)

    def test_session_and_saved_plan_survive_application_restart(self):
        analysis_id = self.analyze()["run_id"]
        saved = self.client.post("/api/plans", json=self.plan_body(analysis_id)).json()["plan"]
        restarted = self.new_client()
        restarted.cookies.set(COOKIE_NAME, self.client.cookies.get(COOKIE_NAME))
        self.assertEqual(restarted.get("/api/plans").json(), [saved])
        self.assertEqual(restarted.get(f"/api/logs/{analysis_id}").status_code, 200)

    def test_swagger_and_openapi(self):
        self.assertEqual(self.client.get("/docs").status_code, 200)
        schema = self.client.get("/openapi.json").json()
        self.assertEqual(set(schema["paths"]["/api/logs/{run_id}"]), {"get", "delete"})
        self.assertIn("APIKeyCookie", schema["components"]["securitySchemes"])
        self.assertIn("examples", schema["components"]["schemas"]["ChatRequest"])

    def test_frontend_html_and_module_assets_are_served_same_origin(self):
        page = self.client.get("/")
        script = self.client.get("/assets/app.js")
        styles = self.client.get("/assets/styles.css")
        self.assertEqual((page.status_code, script.status_code, styles.status_code), (200, 200, 200))
        self.assertIn("SCAMSHIELD AI", page.text)
        self.assertIn("default-src 'self'", page.headers["content-security-policy"])
        self.assertTrue(script.headers["content-type"].startswith("text/javascript"))
        self.assertTrue(styles.headers["content-type"].startswith("text/css"))
