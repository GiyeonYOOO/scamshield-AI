from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.scamshield.assessment import assess
from app.scamshield.planner import PlannerAgent
from app.scamshield_api import create_app


URL = "https://example.com/"
NOW = datetime(2026, 11, 18, 9, tzinfo=timezone.utc)


def google(outcome="NO_MATCH", *, exact=True):
    matches = [] if outcome != "MATCH" else [{"literal_url_match": exact, "threat_types": ["MALWARE"]}]
    return {"ok": True, "outcome": outcome, "data": {"cache_duration": "0s", "matches": matches}}


def report(malicious=1, *, age=0):
    return {"ok": True, "outcome": "REPORT", "data": {
        "last_analysis_date": int(NOW.timestamp()) - age * 3600,
        "last_analysis_stats": {"malicious": malicious, "harmless": 45},
    }}


class TextModeTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.model = Mock()
        self.model.choose.side_effect = [
            [("google_safe_browsing", {})], [("prioritize_action", {"index": 0, "evidence_index": 0})],
        ]
        app = create_app(
            db_path=Path(directory.name) / "quality.sqlite",
            agent_factory=lambda **kw: PlannerAgent(decider=self.model, clock=lambda: NOW, **kw),
        )
        client = TestClient(app, base_url="https://testserver")
        self.addCleanup(client.__exit__, None, None, None)
        self.client = client.__enter__()
        patcher = patch("app.scamshield.tools.providers.run_check", return_value=google())
        self.provider = patcher.start()
        self.addCleanup(patcher.stop)

    def _text_only(self, message):
        response = self.client.post("/api/chat", json={"message": message, "target_type": "text"})
        self.assertEqual(response.status_code, 200)
        analysis = response.json()["analysis"]
        self.assertEqual(analysis["text_assessment"]["url_lookup"], "not_attempted")
        self.assertEqual(analysis["tool_outcomes"], {})
        self.assertEqual(analysis["tool_errors"], {})
        self.provider.assert_not_called()
        self.model.choose.assert_not_called()
        return analysis

    def test_pasted_message_without_link_or_question(self):
        result = self._text_only("즉시 인증번호를 보내고 입금하세요")
        self.assertEqual(result["status"], "SUSPICIOUS")
        self.assertEqual(result["text_assessment"]["status"], "signals_found")
        self.assertIn("긴급 조치 표현", result["local_signals"])

    def test_otp_and_personal_data_request(self):
        result = self._text_only("은행입니다. 주민번호를 제출하고 인증번호를 보내세요.")
        self.assertEqual(set(result["local_signals"]),
                         {"개인정보 요구 표현", "인증정보 요구 표현", "기관 사칭 의심 표현"})

    def test_payment_pressure(self):
        result = self._text_only("오늘까지 수수료를 입금하세요.")
        self.assertEqual(result["status"], "SUSPICIOUS")
        self.assertIn("금전 요구 표현", result["local_signals"])

    def test_benign_message_does_not_create_threat(self):
        for message in ("회의는 내일 오후 3시입니다. 이미 입금이 확인됐습니다.",
                        "인증번호는 공유하지 마세요."):
            with self.subTest(message=message):
                result = self._text_only(message)
                self.assertEqual(result["status"], "INSUFFICIENT_EVIDENCE")
                self.assertEqual(result["text_assessment"]["status"], "no_signals_found")
                self.assertEqual(result["local_signals"], [])

    def test_general_conversation_and_mode_validation_are_preserved(self):
        self.model.choose.side_effect = [[("general_conversation", {})]]
        response = self.client.post("/api/chat", json={"message": "이 서비스는 어떤 일을 하나요?"})
        self.assertEqual(response.json()["analysis"]["status"], "GENERAL")
        bad = self.client.post("/api/chat", json={"message": "hi", "target_type": "unknown"})
        self.assertEqual(bad.status_code, 422)
        self.provider.assert_not_called()

    def test_message_with_url_sends_only_url_to_provider_and_no_body_to_llm(self):
        marker = "private sample wording"
        result = self.client.post("/api/chat", json={
            "message": f"인증번호를 보내세요. {marker} {URL}", "target_type": "text",
        }).json()["analysis"]
        self.assertEqual(result["status"], "SUSPICIOUS")
        self.assertEqual(result["text_assessment"]["url_lookup"], "attempted")
        self.provider.assert_called_once_with("google", URL)
        self.assertNotIn(marker, str(self.model.choose.call_args_list))

    def test_private_link_still_allows_local_analysis(self):
        result = self._text_only(f"인증번호를 보내세요. {URL}?token=example")
        self.assertEqual(result["status"], "SUSPICIOUS")


class ProviderComparisonTests(TestCase):
    def _run(self, first, second, *, vt="virustotal_url", conditions=None):
        return assess({"conditions": conditions or {}, "signals": []},
                      {"google_safe_browsing": first, vt: second}, NOW)

    def test_google_no_match_and_one_engine_is_suspicious_and_different(self):
        result = self._run(google(), report())
        self.assertEqual((result["status"], result["provider_comparison"]), ("SUSPICIOUS", "different"))
        evidence = result["evidence"][1]
        self.assertEqual(evidence["detection_strength"], "single_engine")
        self.assertEqual(evidence["reported_engines"], 46)

    def test_multiple_engine_detections_remain_explicit_despite_no_match(self):
        result = self._run(google(), report(3))
        self.assertEqual((result["status"], result["provider_comparison"]), ("KNOWN_RISK", "different"))
        self.assertEqual(result["evidence"][1]["detection_strength"], "multiple_engines")

    def test_two_providers_detect_on_same_scope(self):
        result = self._run(google("MATCH"), report())
        self.assertEqual((result["status"], result["provider_comparison"]), ("KNOWN_RISK", "agreement"))

    def test_outage_does_not_hide_real_detection_or_create_conflict(self):
        result = self._run({"ok": False, "outcome": "TIMEOUT"}, report(2))
        self.assertEqual(result["status"], "KNOWN_RISK")
        self.assertIsNone(result["provider_comparison"])
        self.assertEqual(result["evidence"][0]["exclusion_reasons"][0]["code"], "API_ERROR")

    def test_positive_observation_outside_requested_period_is_kept_but_excluded(self):
        result = self._run(google(), report(2, age=48), conditions={"max_age_hours": 24})
        self.assertFalse(result["constraints_met"])
        self.assertFalse(result["evidence"][1]["freshness_met"])
        self.assertEqual(result["evidence"][1]["engine_counts"]["malicious"], 2)
        self.assertIsNone(result["provider_comparison"])

    def test_different_scopes_do_not_become_conflicting_verdicts(self):
        result = self._run(google(), report(), vt="virustotal_domain")
        self.assertEqual(result["provider_comparison"], "scope_differs")
        result = self._run(google("MATCH", exact=False), report())
        self.assertEqual(result["provider_comparison"], "scope_differs")

    def test_two_no_detection_observations_do_not_become_a_conflict(self):
        result = self._run(google(), report(0))
        self.assertEqual(result["status"], "NO_KNOWN_MATCH")
        self.assertIsNone(result["provider_comparison"])

    def test_google_match_remains_known_risk_when_vt_reports_no_detection(self):
        result = self._run(google("MATCH"), report(0))
        self.assertEqual((result["status"], result["provider_comparison"]), ("KNOWN_RISK", "different"))
