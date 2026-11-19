from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from app.scamshield import ScamshieldAgent


NOW = datetime(2026, 11, 18, 9, tzinfo=timezone.utc)
URL = "https://example.com/"


def envelope(name, outcome, data=None):
    ok = outcome in {"MATCH", "NO_MATCH", "REPORT", "NO_CANDIDATES", "CANDIDATES"}
    return {
        "check": name, "outcome": outcome, "ok": ok, "data": data,
        "error": None if ok else {"code": outcome, "http_status": None},
    }


def report(hours=2, malicious=0):
    return {
        "last_analysis_date": int((NOW - timedelta(hours=hours)).timestamp()),
        "last_analysis_stats": {"malicious": malicious, "harmless": 15},
    }


class ScamshieldAgentTests(unittest.TestCase):
    def setUp(self):
        calls = patch("app.scamshield.tools.providers.run_check", side_effect=self.provider)
        self.call = calls.start()
        self.addCleanup(calls.stop)
        self.data = {
            "google": ("NO_MATCH", {"matches": [], "cache_duration": "300s"}),
            "vt-url": ("REPORT", report()),
            "urlscan": ("NO_CANDIDATES", {"candidates": []}),
            "vt-domain": ("NO_RECORD", None),
        }
        self.agent = ScamshieldAgent(clock=lambda: NOW, decider=None)

    def provider(self, name, url, days=7):
        self.assertEqual(url, URL)
        outcome, data = self.data[name]
        return envelope(name, outcome, data)

    def invoke(self, message=f"{URL} 검사", session="one"):
        return self.agent.invoke(message, session_id=session)

    def calls(self):
        return [call.args[0] for call in self.call.call_args_list]

    def test_normal_analysis_and_tool_registration(self):
        self.assertEqual(set(self.agent.tools), {
            "google_safe_browsing", "virustotal_url", "urlscan_history", "virustotal_domain",
        })
        self.assertIn("url", self.agent.tools["google_safe_browsing"].args)
        self.assertIn("days", self.agent.tools["urlscan_history"].args)
        result = self.invoke()
        self.assertEqual(result["status"], "NO_KNOWN_MATCH")
        self.assertIn("미탐지", result["message"])
        self.assertEqual(result["replans"], 0)
        self.assertEqual(self.calls(), ["google", "vt-url"])

    def test_known_risk(self):
        self.data["google"] = ("MATCH", {"cache_duration": "300s", "matches": [
            {"literal_url_match": False, "threat_types": ["SOCIAL_ENGINEERING"]},
        ]})
        result = self.invoke()
        self.assertEqual(result["status"], "KNOWN_RISK")
        self.assertEqual(result["evidence"][0]["scope"], "url_expression")
        self.assertTrue(result["actions"])

    def test_partial_failure_keeps_other_tool_results(self):
        self.data["vt-url"] = ("TIMEOUT", None)
        result = self.invoke()
        self.assertIn("google_safe_browsing", result["tool_outcomes"])
        self.assertEqual(result["tool_errors"]["virustotal_url"], "TIMEOUT")
        self.assertEqual(self.calls().count("vt-url"), 1)

    def test_key_and_auth_errors_never_trigger_replan(self):
        for index, code in enumerate(("MISSING_KEY", "AUTH_ERROR")):
            with self.subTest(code=code):
                self.data["vt-url"] = (code, None)
                result = self.invoke(session=str(index))
                self.assertEqual(result["stop_reason"], "UNAVAILABLE_CONFIGURATION")
                self.assertEqual(result["replans"], 0)
                self.assertIn("API 키", result["message"])
        self.assertNotIn("urlscan", self.calls())

    def test_no_search_results_then_alternatives_exhausted(self):
        self.data["vt-url"] = ("NO_RECORD", None)
        result = self.invoke()
        self.assertEqual(result["tool_outcomes"]["urlscan_history"], "NO_CANDIDATES")
        self.assertEqual(result["stop_reason"], "NO_MORE_ALTERNATIVES")
        self.assertEqual(self.calls(), ["google", "vt-url", "urlscan", "vt-domain"])

    def test_replan_uses_recent_scan_without_repeating_successful_tools(self):
        self.data["vt-url"] = ("REPORT", report(hours=100))
        self.data["urlscan"] = ("CANDIDATES", {"candidates": [{
            "scope": "exact_url", "scan_id": "scan-1",
            "observed_at": (NOW - timedelta(hours=3)).isoformat(),
        }]})
        result = self.invoke(f"{URL} 최근 24시간 이내 기록만 정확한 URL 기준으로 검사")
        self.assertTrue(result["constraints_met"])
        self.assertEqual(result["replans"], 1)
        self.assertFalse(result["evidence"][1]["freshness_met"])
        self.assertEqual(self.calls(), ["google", "vt-url", "urlscan"])
        self.assertEqual(self.call.call_args.args[-1], 1)

    def test_replan_limit(self):
        self.agent = ScamshieldAgent(max_replans=1, clock=lambda: NOW, decider=None)
        self.data["vt-url"] = ("NO_RECORD", None)
        result = self.invoke(f"{URL} 최근 24시간 이내 기록만 확인")
        self.assertEqual(result["replans"], 1)
        self.assertEqual(result["stop_reason"], "REPLAN_LIMIT")
        self.assertEqual(result["status"], "INSUFFICIENT_EVIDENCE")
        self.assertNotIn("vt-domain", self.calls())

    def test_when_exact_only_host_observations_cannot_meet_constraints(self):
        self.data["vt-url"] = ("REPORT", report(hours=48))
        self.data["urlscan"] = ("CANDIDATES", {"candidates": [{
            "scope": "same_host", "scan_id": "scan-2", "observed_at": NOW.isoformat(),
        }]})
        result = self.invoke(f"{URL} 최근 24시간 이내 기록만 정확한 URL 기준으로 검사")
        self.assertFalse(result["constraints_met"])
        self.assertFalse(result["evidence"][-1]["scope_met"])
        self.assertNotIn("vt-domain", self.calls())

    def test_session_follow_up_changes_period_and_keeps_scope(self):
        self.invoke(f"{URL} 정확한 URL만 검사")
        result = self.invoke("같은 링크인데 최근 24시간 이내 기록만 확인해 주세요.")
        self.assertEqual(result["conditions"], {"max_age_hours": 24, "exact_only": True})
        self.assertTrue(result["constraints_met"])
        self.assertEqual(self.calls(), ["google", "vt-url", "vt-url"])
        self.assertEqual(self.invoke("같은 링크인데 최근 24시간 이내", session="two")["issue"], "URL_REQUIRED")

    def test_general_chat_has_no_tool_call_even_with_session_memory(self):
        self.invoke()
        self.call.reset_mock()
        self.assertEqual(self.invoke("안녕하세요")["status"], "GENERAL")
        self.call.assert_not_called()

    def test_text_signals_are_local_and_sensitive_url_is_rejected(self):
        result = self.invoke(f"계좌 정지 전에 즉시 인증번호를 입력하라는 문자입니다. {URL}")
        self.assertEqual(result["status"], "SUSPICIOUS")
        self.assertIn("인증정보 요구 표현", result["local_signals"])
        self.call.reset_mock()
        self.assertEqual(self.invoke(f"{URL}?token=private")["issue"], "INVALID_OR_SENSITIVE_URL")
        self.call.assert_not_called()

    def test_text_without_link_can_surface_local_signals(self):
        result = self.invoke("입금 후 인증번호를 보내라는 문자가 왔어요. 사기인가요?")
        self.assertEqual(result["status"], "SUSPICIOUS")
        self.assertEqual(result["issue"], "URL_REQUIRED")
        self.call.assert_not_called()

    def test_exclusions_distinguish_scope_age_no_record_and_api_error(self):
        self.data["google"] = ("TIMEOUT", None)
        self.data["vt-url"] = ("REPORT", report(hours=72))
        self.data["urlscan"] = ("CANDIDATES", {"candidates": [{
            "scope": "same_host", "scan_id": "scope",
            "observed_at": NOW.isoformat(),
        }]})
        result = self.invoke(f"{URL} 최근 24시간 이내 기록만 정확한 URL 기준으로 검사")
        rows = [{reason["code"] for reason in item["exclusion_reasons"]} for item in result["evidence"]]
        self.assertEqual(rows, [{"API_ERROR"}, {"STALE_EVIDENCE", "QUERY_CONDITION_UNMET"},
                                {"URL_SCOPE_MISMATCH", "QUERY_CONDITION_UNMET"}])
        self.assertTrue(all(not item["eligible"] for item in result["evidence"]))

        self.data["vt-url"] = ("NO_RECORD", None)
        self.data["urlscan"] = ("NO_CANDIDATES", {"candidates": []})
        result = self.invoke()
        found = [item for item in result["evidence"] if item["outcome"] == "NO_RECORD"]
        self.assertTrue(found)
        self.assertTrue(all(item["exclusion_reasons"][0]["code"] == "NO_RECORD" for item in found))

    def test_vt_report_supplements_missing_exact_scan_without_extra_lookup(self):
        self.data["vt-url"] = ("REPORT", {**report(hours=72), "exact_candidate_id": "report-id"})
        self.data["urlscan"] = ("NO_CANDIDATES", {"candidates": []})
        result = self.invoke(f"{URL} 최근 24시간 이내 기록만 정확한 URL 기준으로 검사")
        report_row = next(item for item in result["evidence"] if item["tool"] == "virustotal_url")
        self.assertEqual(report_row["supplemental_candidate_id"], "report-id")
        self.assertIn("STALE_EVIDENCE", {reason["code"] for reason in report_row["exclusion_reasons"]})
        self.assertEqual(self.calls(), ["google", "vt-url", "urlscan"])
