from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.scamshield.planner import PlannerAgent
from app.scamshield_api import create_app


REPORTED_RECRUITMENT = "채용 담당자라는 사람에게 본인 확인 메시지를 받았습니다."


class FollowUpTests(TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.app = create_app(
            db_path=Path(temp.name) / "follow-up.sqlite",
            agent_factory=lambda **kw: PlannerAgent(decider=None, max_replans=0, **kw),
        )
        client = TestClient(self.app, base_url="https://testserver")
        self.addCleanup(client.__exit__, None, None, None)
        self.client = client.__enter__()

    def start(self, message=REPORTED_RECRUITMENT, target="text"):
        response = self.client.post("/api/chat", json={"target_type": target, "message": message})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def answer(self, run, question, answer, client=None):
        return (client or self.client).post(f"/api/chat/{run}/follow-up",
                                            json={"question_id": question, "answer": answer})

    def test_message_asks_for_type_then_gives_specific_exposure_guidance(self):
        initial = self.start()
        run = initial["run_id"]
        self.assertEqual(initial["analysis"]["status"], "INSUFFICIENT_EVIDENCE")
        question = initial["follow_up"]["question"]
        self.assertEqual(question["id"], "requested_info")
        self.assertTrue({"id_photo", "otp", "other", "unsure"}.issubset({o["id"] for o in question["options"]}))
        after_type = self.answer(run, "requested_info", "id_photo").json()
        self.assertEqual(after_type["question"]["id"], "interaction")
        self.assertIn("신분증 사진을 보내지", after_type["actions"][0])
        completed = self.answer(run, "interaction", "shared").json()
        self.assertEqual(completed["status"], "completed")
        self.assertIsNone(completed["question"])
        self.assertIn("발급한 기관", completed["actions"][0])
        self.assertEqual(completed["original_verdict"], initial["analysis"]["status"])

    def test_known_requested_type_is_not_asked_again(self):
        result = self.start("은행이라고 하면서 인증번호를 보내라고 했어요.")
        self.assertEqual(result["follow_up"]["question"]["id"], "interaction")

    def test_link_follows_opening_with_information_and_never_requeries_provider(self):
        with patch("app.scamshield.tools.providers.run_check", return_value={"ok": False, "outcome": "TIMEOUT"}) as provider:
            initial = self.start("https://example.com/ 이 링크 검증해 주세요.", "url")
            self.assertEqual(initial["analysis"]["status"], "INSUFFICIENT_EVIDENCE")
            self.assertEqual(initial["follow_up"]["question"]["id"], "interaction")
            calls = provider.call_count
            run = initial["run_id"]
            opened = self.answer(run, "interaction", "viewed").json()
            self.assertEqual(opened["question"]["id"], "requested_info")
            requested = self.answer(run, "requested_info", "otp").json()
            self.assertEqual(requested["question"]["id"], "source")
            completed = self.answer(run, "source", "denied").json()
            self.assertEqual(completed["status"], "completed")
            self.assertEqual(completed["answered_count"], completed["max_questions"])
            self.assertIn("부인", completed["actions"][0])
            self.assertEqual(provider.call_count, calls)

    def test_link_not_opened_goes_directly_to_verification(self):
        with patch("app.scamshield.tools.providers.run_check", return_value={"ok": False, "outcome": "TIMEOUT"}):
            run = self.start("https://example.com/", "url")["run_id"]
        state = self.answer(run, "interaction", "no_action").json()
        self.assertEqual(state["question"]["id"], "source")

    def test_paid_stops_questions_and_gives_priority_action(self):
        run = self.start("긴급히 송금해 달라고 요청했어요.")["run_id"]
        done = self.answer(run, "interaction", "paid").json()
        self.assertEqual(done["status"], "completed")
        self.assertIn("즉시 연락", done["actions"][0])

    def test_skip_stale_and_unlisted_values(self):
        run = self.start()["run_id"]
        self.assertEqual(self.answer(run, "interaction", "paid").status_code, 409)
        self.assertEqual(self.answer(run, "requested_info", "no_action").status_code, 409)
        self.assertEqual(self.answer(run, "requested_info", "123456").status_code, 422)
        skipped = self.answer(run, "requested_info", "skip")
        self.assertEqual(skipped.json()["status"], "skipped")
        self.assertEqual(self.answer(run, "requested_info", "skip").json(), skipped.json())
        self.assertEqual(self.answer(run, "requested_info", "otp").status_code, 409)

    def test_follow_up_is_owned_by_the_session_and_expires(self):
        run = self.start()["run_id"]
        other = TestClient(self.app, base_url="https://testserver")
        self.addCleanup(other.close)
        self.assertEqual(self.answer(run, "requested_info", "otp", other).status_code, 401)
        other.post("/api/chat", json={"message": "안녕하세요"})
        self.assertEqual(self.answer(run, "requested_info", "otp", other).status_code, 404)
        with patch("app.scamshield.follow_up.monotonic", return_value=float("inf")):
            self.assertEqual(self.answer(run, "requested_info", "otp").json()["error"]["code"], "FOLLOW_UP_UNAVAILABLE")

    def test_benign_notice_has_no_follow_up(self):
        result = self.start("내일 오전 10시에 회의실에서 면접을 진행합니다.")
        self.assertIsNone(result["follow_up"])

    def test_call_reuses_request_and_verification(self):
        response = self.client.post("/api/chat", json={
            "target_type": "text",
            "message": "전화로 신분증 사진 제출 요청을 받았어요.",
            "call_context": {"request": "id_photo", "verification": "no"},
        })
        self.assertEqual(response.status_code, 200)
        initial = response.json()
        question = initial["follow_up"]["question"]
        self.assertEqual(question["id"], "interaction")
        self.assertIn("통화", question["prompt"])
        completed = self.answer(initial["run_id"], "interaction", "shared").json()
        self.assertIsNone(completed["question"])
        self.assertIn("발급한 기관", completed["actions"][0])

    def test_call_with_unknown_request_stops_after_known_verification(self):
        initial = self.client.post("/api/chat", json={
            "target_type": "text", "message": "전화에서 무언가를 요청했어요.",
            "call_context": {"request": "other", "verification": "denied"},
        }).json()
        run = initial["run_id"]
        self.assertEqual(initial["follow_up"]["question"]["id"], "requested_info")
        self.assertEqual(self.answer(run, "requested_info", "otp").json()["question"]["id"], "interaction")
        done = self.answer(run, "interaction", "no_action").json()
        self.assertIsNone(done["question"])
        self.assertIn("부인", done["actions"][0])

    def test_call_with_verified_contact_and_unspecified_request_still_offers_follow_up(self):
        response = self.client.post("/api/chat", json={
            "target_type": "text", "message": "전화로 연락을 받았어요. 기존 번호로 확인했어요.",
            "call_context": {"request": "other", "verification": "yes"},
        })
        self.assertEqual(response.status_code, 200)
        initial = response.json()
        self.assertEqual(initial["follow_up"]["question"]["id"], "requested_info")
        run = initial["run_id"]
        self.assertEqual(self.answer(run, "requested_info", "unsure").json()["question"]["id"], "interaction")
        self.assertEqual(self.answer(run, "interaction", "no_action").json()["status"], "completed")

    def test_call_already_sent_shows_advice_without_another_question(self):
        result = self.client.post("/api/chat", json={
            "target_type": "text", "message": "전화가 왔고 이미 돈을 보냈어요.",
            "call_context": {"request": "transfer", "verification": "no", "already_sent": True},
        }).json()
        self.assertIsNone(result["follow_up"]["question"])
        self.assertIn("즉시 연락", result["follow_up"]["actions"][0])

    def test_optional_call_note_informs_follow_up_without_url_lookup(self):
        with patch("app.scamshield.tools.providers.run_check") as provider:
            response = self.client.post("/api/chat", json={
                "target_type": "text", "message": "전화로 연락을 받았어요.",
                "context_note": "신분증 사진을 보내라고 했어요. https://example.com/check",
                "call_context": {"request": "other", "verification": "no"},
            })
        self.assertEqual(response.status_code, 200, response.text)
        initial = response.json()
        self.assertEqual(initial["analysis"]["text_assessment"]["url_lookup"], "not_attempted")
        provider.assert_not_called()
        self.assertEqual(initial["follow_up"]["question"]["id"], "interaction")
        done = self.answer(initial["run_id"], "interaction", "shared").json()
        self.assertIn("발급한 기관", done["actions"][0])
