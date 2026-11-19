from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import date, datetime, time
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest

from app.scamshield import ScamshieldAgent
from app.scamshield.events import EventBus
from app.scamshield.execution_logs import ExecutionLogs, LoggingAgent
from app.scamshield.prevention_plans import PreventionPlans


class PreventionPlanTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "shared.sqlite"
        self.logs = ExecutionLogs(self.path)
        self.addCleanup(self.logs.close)
        self.plans = PreventionPlans(self.path)
        self.addCleanup(self.plans.close)
        bus = EventBus()
        bus.subscribe(LoggingAgent(self.logs).record)
        self.agent = ScamshieldAgent(decider=None, event_bus=bus)
        self.response, self.draft = self.analyze("alice")

    def analyze(self, owner):
        return self.agent.invoke_for_plan(
            "문자에서 입금과 인증번호를 요구합니다. 사기인가요?",
            session_id=owner, target_type="text",
        )

    def save(self, start="09:00", end="10:00", *, date="2026-11-18",
             owner="alice", draft=None, title="예방 계획"):
        return self.plans.save_from_analysis(
            owner, self.draft if draft is None else draft,
            title=title, execution_date=date, start_time=start, end_time=end,
        )

    def test_agent_draft_requires_explicit_save_and_links_to_run(self):
        self.assertEqual(self.plans.list_plans("alice"), [])
        saved = self.save(date=date(2026, 11, 18), start=time(9), end=time(10))
        plan = saved.plan
        self.assertEqual(plan.analysis_id, self.logs.list_runs("alice")[0]["run_id"])
        self.assertEqual(plan.actions, tuple(self.response["actions"]))
        self.assertEqual((plan.target_type, plan.start_time, plan.end_time), ("text", "09:00:00", "10:00:00"))
        self.assertEqual(plan.created_at, plan.updated_at)
        self.assertIsNotNone(datetime.fromisoformat(plan.created_at).utcoffset())
        self.assertEqual(self.plans.get_plan("alice", plan.id), plan)
        self.assertFalse(saved.has_overlap)

    def test_overlapping_saves_succeed_but_touching_or_other_dates_do_not_overlap(self):
        first = self.save().plan
        touching = self.save("10:00", "11:00")
        overlap = self.save("09:30", "09:45")
        other_day = self.save(date="2026-11-19")
        self.assertEqual(overlap.overlapping_plan_ids, (first.id,))
        self.assertTrue(overlap.has_overlap)
        self.assertFalse(touching.has_overlap)
        self.assertFalse(other_day.has_overlap)
        self.assertEqual(self.plans.list_plans("alice"), [first, overlap.plan, touching.plan, other_day.plan])

    def test_update_rechecks_overlap_excluding_itself_and_delete_is_immediate(self):
        first = self.save().plan
        second = self.save("10:00", "11:00", date="2026-11-19").plan
        updated = self.plans.update_plan(
            "alice", second.id, title="수정된 계획", actions=["공식 번호로 연락"],
            execution_date="2026-11-18", start_time="09:30", end_time="10:30",
        )
        self.assertEqual(updated.overlapping_plan_ids, (first.id,))
        self.assertEqual(updated.plan.actions, ("공식 번호로 연락",))
        self.assertEqual(updated.plan.title, "수정된 계획")
        self.assertEqual(updated.plan.created_at, second.created_at)
        self.assertGreaterEqual(updated.plan.updated_at, second.updated_at)
        self.assertEqual(self.plans.get_plan("alice", second.id), updated.plan)
        self.assertTrue(self.plans.delete_plan("alice", second.id))
        self.assertFalse(self.plans.delete_plan("alice", second.id))
        self.assertIsNone(self.plans.get_plan("alice", second.id))
        self.assertEqual(self.plans.list_plans("alice"), [first])

    def test_other_owner_cannot_access_modify_delete_or_save_another_owners_draft(self):
        alice = self.save().plan
        self.assertIsNone(self.plans.get_plan("bob", alice.id))
        self.assertIsNone(self.plans.update_plan("bob", alice.id, title="타인 변경"))
        self.assertFalse(self.plans.delete_plan("bob", alice.id))
        with self.assertRaises(PermissionError):
            self.save(owner="bob")
        _, bob_draft = self.analyze("bob")
        bob = self.save(owner="bob", draft=bob_draft)
        self.assertFalse(bob.has_overlap)
        self.assertEqual(self.plans.list_plans("alice"), [alice])
        self.assertEqual(self.plans.list_plans("bob"), [bob.plan])

    def test_invalid_date_time_and_invalid_partial_update_rollback(self):
        for values in (
            {"date": "2026-02-30"}, {"date": "20261118"}, {"start": "24:00"},
            {"start": "09:00+09:00"}, {"start": "10:00"}, {"start": "23:00", "end": "00:00"},
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.save(**values)
        self.assertEqual(self.plans.list_plans("alice"), [])
        valid = self.save().plan
        with self.assertRaises(ValueError):
            self.plans.update_plan("alice", valid.id, title="변경 실패", end_time="08:00")
        self.assertEqual(self.plans.get_plan("alice", valid.id), valid)

    def test_raw_response_and_sensitive_url_do_not_enter_plan_store(self):
        with self.assertRaises(TypeError):
            self.save(draft=self.response)
        saved = self.save(title="확인 https://example.com/?token=secret").plan
        updated = self.plans.update_plan("alice", saved.id, actions=["공식 연락 user@example.com"]).plan
        self.assertEqual(updated.title, "확인 [가림]")
        self.assertEqual(updated.actions, ("공식 연락 [가림]",))
        with closing(sqlite3.connect(self.path)) as db:
            stored = db.execute("SELECT title, actions FROM prevention_plans").fetchone()
        self.assertNotIn("example.com", repr(stored))
        self.assertIsNone(self.agent.invoke_for_plan("안녕하세요", session_id="greeting")[1])

    def test_shared_database_existing_logs_remain_intact(self):
        before = self.logs.get_events("alice")
        self.assertTrue(before)
        plan = self.save().plan
        self.assertTrue(self.plans.delete_plan("alice", plan.id))
        self.assertEqual(self.logs.get_events("alice"), before)
        self.agent.invoke("안녕하세요", session_id="alice")
        self.assertEqual(len(self.logs.list_runs("alice")), 2)

    def test_concurrent_saves_check_overlap_in_write_transaction(self):
        other = PreventionPlans(self.path)
        self.addCleanup(other.close)
        barrier = Barrier(2, timeout=5)

        def save(service):
            barrier.wait()
            return service.save_from_analysis(
                "alice", self.draft, title="동시 저장", execution_date="2026-11-18",
                start_time="09:00", end_time="10:00",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(save, (self.plans, other)))
        self.assertEqual(sorted(result.has_overlap for result in results), [False, True])
        self.assertEqual(len(self.plans.list_plans("alice")), 2)
