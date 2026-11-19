import json
import unittest
from unittest.mock import Mock, patch

import requests

from app.scamshield import ScamshieldAgent
from app.scamshield.llm import OpenAICompatibleDecider


URL = "https://example.com/"


def model_response(*functions):
    return Mock(status_code=200, json=Mock(return_value={
        "choices": [{"message": {"tool_calls": [
            {"type": "function", "function": {"name": name, "arguments": json.dumps(args)}}
            for name, args in functions
        ]}}],
    }))


class AgentFunctionCallingTests(unittest.TestCase):
    def setUp(self):
        model = patch("app.scamshield.llm.requests.post")
        providers = patch("app.scamshield.tools.providers.run_check", side_effect=self.lookup)
        self.post = model.start()
        self.provider = providers.start()
        self.addCleanup(model.stop)
        self.addCleanup(providers.stop)
        self.decider = OpenAICompatibleDecider("https://example.com/v1", "test-model", "mock-key")
        self.agent = ScamshieldAgent(decider=self.decider)

    @staticmethod
    def lookup(name, url, days=7):
        results = {
            "google": ("NO_MATCH", {"matches": [], "cache_duration": "300s"}),
            "vt-url": ("NO_RECORD", None),
            "vt-domain": ("NO_RECORD", None),
            "urlscan": ("NO_CANDIDATES", {"candidates": []}),
        }
        outcome, data = results[name]
        return {"check": name, "outcome": outcome, "data": data,
                "ok": outcome != "NO_RECORD", "error": None}

    def test_model_chooses_tool_order_and_presentation(self):
        self.post.side_effect = [
            model_response(("virustotal_url", {}), ("google_safe_browsing", {})),
            model_response(("finish_without_lookup", {})),
            model_response(("prioritize_action", {"index": 1, "evidence_index": 1})),
        ]
        result = self.agent.invoke(f"{URL} 검사", session_id="ordered")
        self.assertEqual([call.args for call in self.provider.call_args_list],
                         [("vt-url", URL), ("google", URL)])
        self.assertEqual(result["status"], "NO_KNOWN_MATCH")
        self.assertEqual(result["stop_reason"], "LLM_NO_USEFUL_ALTERNATIVE")
        self.assertEqual(result["decisions"][0]["source"], "llm")
        self.assertEqual(result["assessment_source"], "rules")
        self.assertEqual(result["highlighted_evidence"]["tool"], "google_safe_browsing")
        self.assertNotIn(URL, self.post.call_args_list[0].kwargs["json"]["messages"][1]["content"])

    def test_model_selects_an_unused_replan_tool(self):
        self.agent = ScamshieldAgent(decider=self.decider, max_replans=1)
        self.post.side_effect = [
            model_response(("virustotal_url", {})),
            model_response(("urlscan_history", {})),
            model_response(("prioritize_action", {"index": 0, "evidence_index": 0})),
        ]
        result = self.agent.invoke(f"{URL} 검사", session_id="replan")
        self.assertEqual(result["replans"], 1)
        self.assertEqual(result["decisions"][1]["choices"], ["urlscan_history"])
        self.assertEqual([call.args[0] for call in self.provider.call_args_list], ["vt-url", "urlscan"])
        offered = self.post.call_args_list[1].kwargs["json"]["tools"]
        self.assertNotIn("virustotal_url", [item["function"]["name"] for item in offered])
        self.assertEqual(self.post.call_count, 2)

    def test_simple_greeting_skips_both_apis(self):
        result = self.agent.invoke("안녕하세요!", session_id="greeting")
        self.assertEqual(result["status"], "GENERAL")
        self.post.assert_not_called()
        self.provider.assert_not_called()

    def test_model_detects_general_intent_without_security_lookup(self):
        self.post.return_value = model_response(("general_conversation", {}))
        result = self.agent.invoke("이 서비스에서 사기 검사는 어떻게 진행해요?", session_id="help")
        self.assertEqual(result["status"], "GENERAL")
        self.post.assert_called_once()
        self.provider.assert_not_called()

    def test_untrusted_tool_arguments_cannot_change_lookup_target(self):
        self.post.return_value = model_response(("google_safe_browsing", {"url": "https://example.org/"}))
        result = self.agent.invoke(f"{URL} 검사", session_id="guard")
        self.assertEqual(result["llm_error"], "LLM_REJECTED_CHOICE")
        self.assertTrue(all(call.args[1] == URL for call in self.provider.call_args_list))
        self.post.assert_called_once()

    def test_llm_auth_error_falls_back_without_retry(self):
        self.post.return_value = Mock(status_code=401)
        result = self.agent.invoke(f"{URL} 검사", session_id="fallback")
        self.assertEqual(result["llm_error"], "LLM_AUTH_ERROR")
        self.assertEqual(result["decisions"][0]["source"], "rules")
        self.assertIn("google_safe_browsing", result["tool_outcomes"])
        self.post.assert_called_once()

    def test_text_only_completion_falls_back_once_without_claiming_llm_selection(self):
        self.post.return_value = Mock(status_code=200, json=Mock(return_value={
            "choices": [{"finish_reason": "stop", "message": {"content": "I'll explain it."}}],
        }))
        result = self.agent.invoke(URL, session_id="text-only")
        self.assertEqual(result["llm_error"], "LLM_TOOL_CALL_MISSING")
        self.assertTrue(all(item["source"] == "rules" for item in result["decisions"]))
        self.assertEqual(self.post.call_args.kwargs["json"]["tool_choice"], "required")
        self.post.assert_called_once()

    def test_parser_rejects_unlisted_tool_and_nonobject_arguments_distinctly(self):
        for name, args, code in (
            ("not_offered", {}, "LLM_UNKNOWN_TOOL"),
            ("google_safe_browsing", [], "LLM_INVALID_ARGUMENTS"),
        ):
            with self.subTest(code=code):
                self.post.return_value = model_response((name, args))
                result = self.agent.invoke(URL, session_id=code)
                self.assertEqual(result["llm_error"], code)

    def test_explicit_single_provider_is_enforced_on_model_and_fallback(self):
        self.post.return_value = model_response(("virustotal_url", {}))
        result = self.agent.invoke(
            f"Check {URL} using only Google Safe Browsing.", session_id="scope",
        )
        options = [tool["function"]["name"] for tool in self.post.call_args.kwargs["json"]["tools"]]
        self.assertNotIn("virustotal_url", options)
        self.assertEqual(result["llm_error"], "LLM_UNKNOWN_TOOL")
        self.assertEqual(list(result["tool_outcomes"]), ["google_safe_browsing"])
        self.post.assert_called_once()

    def test_decision_timeout_switches_to_rules_without_retry(self):
        self.post.side_effect = requests.ReadTimeout()
        result = self.agent.invoke(f"Check {URL} using only Google Safe Browsing.", session_id="timeout")
        self.assertEqual(self.post.call_args.kwargs["timeout"], (3, 6))
        self.assertEqual(result["llm_error"], "LLM_TIMEOUT")
        self.assertEqual(result["tool_outcomes"], {"google_safe_browsing": "NO_MATCH"})
        self.assertTrue(all(item["source"] == "rules" for item in result["decisions"]))
        self.post.assert_called_once()

    def test_presentation_timeout_preserves_confirmed_evidence_and_actions(self):
        self.post.side_effect = [model_response(("google_safe_browsing", {})), requests.ReadTimeout()]
        result = self.agent.invoke(URL, session_id="presentation")
        self.assertEqual([call.kwargs["timeout"] for call in self.post.call_args_list], [(3, 6), (3, 3)])
        self.assertEqual(result["llm_error"], "LLM_TIMEOUT")
        self.assertEqual(result["status"], "NO_KNOWN_MATCH")
        self.assertTrue(result["actions"])
        self.assertTrue(result["evidence"][0]["eligible"])
        self.provider.assert_called_once()
