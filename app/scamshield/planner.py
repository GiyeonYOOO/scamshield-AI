"""F3021: Planner orchestrates Worker execution and independent log verification."""

from .agent import ScamshieldAgent
from .assessment import DEFAULT_FRESHNESS_HOURS
from .execution_logs import LoggingAgent
from .work import PlanBatch, Task, ToolArguments, WorkerAgent


class PlannerAgent(ScamshieldAgent):
    """Reuse the LangGraph, public responses and memory of the single Agent."""

    def __init__(self, *, logging_agent=None, enable_worker_llm=True, **kwargs):
        self.logging_agent = logging_agent if logging_agent is not None else LoggingAgent(None)
        self.worker = WorkerAgent(enable_llm=enable_worker_llm)
        super().__init__(**kwargs)

    @staticmethod
    def _make_batch(state, names, revision):
        run = state["run"]
        request = state["request"]
        conditions = request["conditions"]
        hours = conditions.get("max_age_hours", DEFAULT_FRESHNESS_HOURS)
        tasks = []
        for index, name in enumerate(names, 1):
            days = (hours + 23) // 24 if name == "urlscan_history" else None
            fixed = frozenset({"url", "days"} if days is not None and "max_age_hours" in conditions else {"url"})
            task = Task(run.run_id, revision * 100 + index, name,
                        ToolArguments(request["url"], days), fixed, tuple(sorted(conditions.items())))
            tasks.append(task)
            run.emit("planner.task", task_id=task.task_id, revision=revision, tool=name,
                     days=days, fixed_url=True, fixed_days="days" in fixed, input_url=request["url"])
        return PlanBatch(run.run_id, revision, tuple(tasks))

    def _plan(self, state):
        update = super()._plan(state)
        return {**update, "batch": self._make_batch(state, update["pending"], state["replans"])}

    def _execute(self, state):
        run = state["run"]
        plan = state["batch"]
        start = len(run.audit_events)
        decider = None if state.get("llm_error") else self.decider
        work = self.worker.execute(plan, self._call_tool, run, decider)
        worker_error = next((item.llm_error for item in work if item.llm_error), None)
        events = run.audit_events[start:]
        previous_calls = state.get("attempted_calls", set())
        verification = self.logging_agent.verify(
            plan, work, events, previous_calls, self.max_replans, run, None if worker_error else decider,
        )
        results = dict(state["results"])
        for entry in verification.accepted:
            results[entry.task.tool] = entry.attempts[-1].result if entry.attempts else {
                "check": entry.task.tool, "outcome": "INVALID_INPUT", "ok": False,
                "data": None, "error": {"code": "INVALID_INPUT", "http_status": None},
            }
        calls = {(attempt.tool, attempt.arguments) for entry in work for attempt in entry.attempts}
        tools = {event.data["tool"] for event in events
                 if event.event_type == "tool.requested" and "tool" in event.data}
        return {
            "results": results, "verification": verification, "attempted_calls": previous_calls | calls,
            "attempted_tool_names": state.get("attempted_tool_names", set()) | tools,
            "llm_error": worker_error or verification.llm_error or state.get("llm_error"),
        }

    def _judge(self, state):
        verification = state["verification"]
        if verification.request_plan_change:
            reason = "AUDIT_ANOMALY"
        elif any(item.request_plan_change and not (
            verification.status == "needs_review" and item.failure_code == "INCOMPLETE_REPORT"
        ) for item in verification.accepted):
            reason = "WORKER_REQUESTED_CHANGE"
        else:
            reason = ""
        return {**super()._judge({**state, "replan_reason": reason}), "replan_reason": reason}

    def _replan(self, state):
        update = super()._replan(state)
        if update.get("stop_reason"):
            return update
        return {**update, "batch": self._make_batch(state, update["pending"], update["replans"])}
