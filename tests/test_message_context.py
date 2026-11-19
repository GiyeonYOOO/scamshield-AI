from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.scamshield.events import EventBus
from app.scamshield.llm import DecisionError, OpenAICompatibleDecider
from app.scamshield.message_context import CONTEXT_TOOL
from app.scamshield.planner import PlannerAgent
from app.scamshield_api import create_app


RECRUIT = "채용 담당자입니다. 서류 확인을 위해 별도 페이지에서 본인 확인을 진행해 주세요."
NOW = datetime(2026, 11, 19, tzinfo=timezone.utc)
NO_MATCH = {"ok": True, "outcome": "NO_MATCH", "data": {"cache_duration": "0s", "matches": []}}


def findings(*entries, unknowns=(), checks=(), actions=()):
    return [(CONTEXT_TOOL, {
        "findings": [{"category": category, "evidence_id": index} for category, index in entries],
        "unknowns": list(unknowns),
        "checks": list(checks),
        "actions": list(actions),
    })]


class MessageContextTests(TestCase):
    def setUp(self):
        self.model = Mock()
        self.model.choose.return_value = findings()
        self.events = []
        bus = EventBus()
        bus.subscribe(self.events.append)
        self.agent = PlannerAgent(decider=self.model, clock=lambda: NOW, event_bus=bus)
        provider = patch("app.scamshield.tools.providers.run_check", return_value=NO_MATCH)
        self.provider = provider.start()
        self.addCleanup(provider.stop)

    def analyze(self, text, *, owner="owner", opted_in=True):
        return self.agent.invoke(text, session_id=owner, target_type="text", context_analysis=opted_in)

    def test_subtle_recruitment_has_grounded_context_without_upgrading_verdict(self):
        self.model.choose.return_value = findings(
            ("claimed_role", 1),
            ("off_platform", 2),
            ("data_collection", 2),
            unknowns=("sender_identity", "official_process"),
        )
        result = self.analyze(RECRUIT)
        self.assertEqual(result["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["assessment_source"], "rules")
        context = result["text_assessment"]["context"]
        self.assertEqual(len(context["facts"]), 2)
        self.assertEqual(len(context["signals"]), 2)
        self.assertEqual(len(context["unknowns"]), 4)
        self.assertTrue(all(item["quote"] in RECRUIT for item in context["facts"] + context["signals"]))
        self.provider.assert_not_called()
        self.assertNotIn(RECRUIT, str([dict(event.data) for event in self.events]))

    def test_clear_request_preserves_rule_verdict(self):
        message = "은행입니다. 즉시 인증번호를 보내세요."
        self.model.choose.return_value = findings(("data_collection", 2))
        result = self.analyze(message)
        self.assertEqual(result["status"], "SUSPICIOUS")
        self.assertIn("인증정보 요구 표현", result["local_signals"])
        self.assertEqual(result["text_assessment"]["context"]["status"], "analyzed")

    def test_benign_work_notice_and_general_text(self):
        for text in ("내일 회의는 오전 열 시에 시작합니다.", "안녕하세요. 잘 지내시나요?"):
            with self.subTest(text=text):
                result = self.analyze(text)
                self.assertEqual(result["local_signals"], [])
                self.assertEqual(result["text_assessment"]["context"]["signals"], [])
                self.assertNotEqual(result["status"], "SUSPICIOUS")
        self.provider.assert_not_called()

    def test_opt_out_preserves_no_message_body_sharing(self):
        self.assertNotIn("context", self.analyze(RECRUIT, opted_in=False)["text_assessment"])
        self.model.choose.assert_not_called()

    def test_cache_is_scoped_to_session(self):
        self.analyze(RECRUIT)
        self.analyze(RECRUIT)
        self.model.choose.assert_called_once()
        self.analyze(RECRUIT, owner="other")
        self.assertEqual(self.model.choose.call_count, 2)

    def test_timeout_and_unverifiable_output_fall_back(self):
        bad = [
            DecisionError("LLM_TIMEOUT"),
            findings(("off_platform", 999)),
            [("google_safe_browsing", {})],
        ]
        self.model.choose.side_effect = bad
        for reason in ("LLM_TIMEOUT", "LLM_CONTEXT_REFERENCE_INVALID", "LLM_CONTEXT_SCHEMA_INVALID"):
            result = self.analyze(RECRUIT)
            self.assertEqual(result["text_assessment"]["context"]["status"], "rules_only")
            self.assertEqual(result["text_assessment"]["context"]["reason"], reason)
            self.assertEqual(result["status"], "INSUFFICIENT_EVIDENCE")
            self.assertEqual(next(event for event in reversed(self.events)
                                  if event.event_type == "message_context.finished").data["reason"], reason)
        self.provider.assert_not_called()

    def test_mixed_message_keeps_lookup_and_redacts_model_context(self):
        choices = {
            "intent_and_plan": [("google_safe_browsing", {})],
            "response": [("prioritize_action", {"index": 0, "evidence_index": 0})],
            "message_context": findings(("data_collection", 1)),
        }
        self.model.choose.side_effect = lambda stage, *_: choices[stage]
        url = "https://example.com/"
        result = self.analyze(f"인증번호를 보내세요. OTP: 918273 contact@example.net {url}")
        self.provider.assert_called_once_with("google", url)
        self.assertEqual(result["text_assessment"]["url_lookup"], "attempted")
        self.assertEqual(result["text_assessment"]["context"]["status"], "analyzed")
        _, instructions, payload, offered = next(
            call.args for call in self.model.choose.call_args_list if call.args[0] == "message_context"
        )
        self.assertIn("untrusted", instructions)
        text = "".join(part["text"] for part in payload["evidence"])
        self.assertNotIn("918273", text)
        self.assertNotIn("contact@example.net", text)
        self.assertNotIn(url, text)
        self.assertEqual([item["function"]["name"] for item in offered], [CONTEXT_TOOL])

    def test_private_url_is_never_sent(self):
        result = self.analyze("별도 페이지를 사용하세요. https://example.com/?token=privatevalue")
        self.provider.assert_not_called()
        self.assertNotIn("privatevalue", str(self.model.choose.call_args.args))
        self.assertEqual(result["text_assessment"]["url_lookup"], "not_attempted")

    def test_benign_quotes_do_not_support_unrelated_categories(self):
        self.model.choose.return_value = findings(
            ("data_collection", 2),
            ("off_platform", 1),
            unknowns=("destination", "data_handling"),
        )
        result = self.analyze("내일 회의실에서 진행합니다. 지난 회의록을 읽고 참석해 주세요.")
        self.assertEqual(result["text_assessment"]["context"]["signals"], [])
        self.assertEqual(result["text_assessment"]["context"]["unknowns"], [])

    def test_combined_external_identity_check_is_labeled_as_rule_support(self):
        result = self.analyze(RECRUIT)
        context = result["text_assessment"]["context"]
        self.assertEqual([entry["source"] for entry in context["signals"]], ["rules", "rules"])
        self.assertEqual(result["status"], "INSUFFICIENT_EVIDENCE")

    def test_http_public_schema_serializes_opted_in_context(self):
        self.model.choose.return_value = findings(("identity_verification", 1))
        with TemporaryDirectory() as tmp:
            app = create_app(db_path=Path(tmp) / "test.sqlite3",
                             agent_factory=lambda **kwargs: PlannerAgent(decider=self.model, **kwargs))
            with TestClient(app) as client:
                response = client.post("/api/chat", json={
                    "message": RECRUIT, "target_type": "text", "context_analysis": True,
                })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["analysis"]["text_assessment"]["context"]["signals"][0]["quote"],
                         "채용 담당자입니다.")

    def test_reported_recruitment_keeps_identity_and_request_unverified(self):
        message = "채용 담당자라는 사람에게 본인 확인 메시지를 받았습니다."
        self.model.choose.return_value = findings(
            ("data_collection", 1), ("claimed_role", 1), ("requested_step", 1),
            unknowns=("data_handling",), checks=("data_handling",),
        )
        result = self.analyze(message)
        context = result["text_assessment"]["context"]
        self.assertEqual(result["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual([item["quote"] for item in context["facts"]], [message, message])
        self.assertEqual(len(context["signals"]), 1)
        self.assertIn("어떤 정보나 절차", " ".join(context["unknowns"]))
        self.assertIn("공식 창구", " ".join(context["checks"]))
        self.assertIn("공식 채용", " ".join(context["actions"]))

    def test_normal_recruitment_notice_needs_no_added_warning(self):
        self.model.choose.return_value = findings(("off_platform", 1), ("payment", 1))
        result = self.analyze("면접은 내일 오전 10시에 본사 회의실에서 진행됩니다.")
        self.assertEqual(result["text_assessment"]["context"]["signals"], [])
        self.assertEqual(result["status"], "INSUFFICIENT_EVIDENCE")

    def test_payment_pressure_advice_does_not_change_verdict(self):
        message = "오늘까지 수수료를 입금하세요."
        self.model.choose.return_value = findings(("payment", 1), ("pressure", 1), actions=("hold_payment",))
        result = self.analyze(message)
        self.assertEqual(result["status"], "SUSPICIOUS")
        self.assertIn("송금하지", result["text_assessment"]["context"]["actions"][0])

    def test_transport_uses_context_timeout_and_surfaces_invalid_json(self):
        model = OpenAICompatibleDecider("https://example.com/v1", "gpt-5-nano", "fake-key")
        self.agent.decider = model
        response = Mock(status_code=200)
        response.json.return_value = {"choices": [{"finish_reason": "tool_calls", "message": {
            "tool_calls": [{"type": "function", "function": {"name": CONTEXT_TOOL, "arguments": "{"}}],
        }}]}
        with patch("app.scamshield.llm.requests.post", return_value=response) as transport:
            result = self.analyze(RECRUIT)
        self.assertEqual(result["text_assessment"]["context"]["reason"], "LLM_INVALID_ARGUMENTS")
        self.assertEqual(transport.call_args.kwargs["timeout"], (3, 15))
        self.assertEqual(transport.call_args.kwargs["json"]["tool_choice"]["function"]["name"], CONTEXT_TOOL)
        self.assertFalse(transport.call_args.kwargs["json"]["parallel_tool_calls"])

    def test_url_context_note_does_not_change_what_providers_receive(self):
        choices = {
            "intent_and_plan": [("google_safe_browsing", {})],
            "response": [("prioritize_action", {"index": 0, "evidence_index": 0})],
            "message_context": findings(("data_collection", 1)),
        }
        self.model.choose.side_effect = lambda stage, *_: choices[stage]
        link = "https://example.com/"
        note = "별도 페이지에서 본인 확인을 진행해 주세요. https://example.net/?token=fakevalue"
        with TemporaryDirectory() as tmp:
            app = create_app(db_path=Path(tmp) / "test.sqlite3",
                             agent_factory=lambda **kwargs: PlannerAgent(decider=self.model, **kwargs))
            with TestClient(app) as client:
                response = client.post("/api/chat", json={
                    "message": link, "target_type": "url", "context_analysis": True, "context_note": note,
                })
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["analysis"]["message_context"]["status"], "analyzed")
        self.assertIsNotNone(result["follow_up"])
        self.provider.assert_called_once_with("google", link)
        _, _, payload, _ = next(call.args for call in self.model.choose.call_args_list if call.args[0] == "message_context")
        self.assertNotIn(link, str(payload))
        self.assertNotIn("fakevalue", str(payload))

    def test_call_opt_in_reuses_context_and_follow_up(self):
        self.model.choose.return_value = findings(("data_collection", 1))
        with TemporaryDirectory() as tmp:
            app = create_app(db_path=Path(tmp) / "test.sqlite3",
                             agent_factory=lambda **kwargs: PlannerAgent(decider=self.model, **kwargs))
            with TestClient(app) as client:
                response = client.post("/api/chat", json={
                    "message": "전화로 신분증 사진 제출을 요청했어요.", "target_type": "text",
                    "context_analysis": True, "call_context": {"request": "id_photo", "verification": "no"},
                })
        result = response.json()
        self.assertEqual(result["analysis"]["text_assessment"]["context"]["status"], "analyzed")
        self.assertEqual(result["follow_up"]["question"]["id"], "interaction")
        self.provider.assert_not_called()
