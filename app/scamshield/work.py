"""F3021 messages and Worker execution."""

from dataclasses import dataclass, field, replace
from typing import Literal

from .llm import DecisionError, function
from .message_context import analyze_message_context
from .tools import ToolResult


RECOVERABLE = {"NO_CANDIDATES", "NO_RECORD", "REQUEST_REJECTED"}
WORKER_ACTIONS = {"retry_same_tool", "skip_task", "request_new_plan"}


@dataclass(frozen=True)
class ToolArguments:
    url: str = field(repr=False)
    days: int | None = None

    def as_kwargs(self):
        return {"url": self.url} if self.days is None else {"url": self.url, "days": self.days}


@dataclass(frozen=True)
class Task:
    run_id: str
    task_id: int
    tool: str
    arguments: ToolArguments
    fixed_arguments: frozenset[str]
    fixed_conditions: tuple[tuple[str, int | bool], ...]


@dataclass(frozen=True)
class PlanBatch:
    run_id: str
    revision: int
    tasks: tuple[Task, ...]


@dataclass(frozen=True)
class Attempt:
    run_id: str
    task_id: int
    tool: str
    arguments: ToolArguments
    number: int
    result: ToolResult = field(repr=False)


@dataclass(frozen=True)
class WorkResult:
    task: Task
    attempts: tuple[Attempt, ...]
    failure_code: str | None
    request_plan_change: bool
    llm_error: str | None = None

    @property
    def retried(self):
        return len(self.attempts) > 1


@dataclass(frozen=True)
class ValidationResult:
    status: Literal["verified", "anomaly", "needs_review"]
    codes: tuple[str, ...]
    accepted: tuple[WorkResult, ...]
    request_plan_change: bool
    llm_error: str | None = None


class WorkerAgent:
    """Run a plan and alter only a Planner-owned default lookback, at most once."""

    max_retries = 1

    def __init__(self, *, enable_llm=True):
        self.enable_llm = enable_llm

    @staticmethod
    def interpret_message(text, decider, cache, run):
        return analyze_message_context(text, decider, cache, run)

    def execute(self, plan, invoke_tool, run, decider=None):
        results = []
        for task in plan.tasks:
            result = self._execute_task(task, invoke_tool, run, decider)
            results.append(result)
            if result.llm_error:
                decider = None
        return tuple(results)

    def _execute_task(self, task, invoke_tool, run, decider):
        if not self.valid_input(task):
            run.emit("worker.decision", task_id=task.task_id, action="request_new_plan",
                     llm_called=False, retried=False, request_plan_change=True, outcome="INVALID_INPUT")
            run.emit("error.handled", code="INVALID_INPUT", handling="continue")
            return WorkResult(task, (), "INVALID_INPUT", True)
        first = self._attempt(task, task.arguments, 1, invoke_tool, run)
        attempts = (first,)
        failed = not first.result["ok"] or first.result["outcome"] == "NO_CANDIDATES"
        action = "complete" if not failed else "request_new_plan"
        llm_called = False
        llm_error = None
        if failed:
            days = self.retry_days(task, first.result["outcome"])
            if days is not None and self.enable_llm and decider is not None:
                llm_called = True
                action, llm_error = self._choose(decider, task, first.result["outcome"], days, run)
                if action == "retry_same_tool" and self.max_retries >= 1:
                    arguments = replace(task.arguments, days=days)
                    retry = self._attempt(task, arguments, 2, invoke_tool, run)
                    attempts += (retry,)
                    failed = not retry.result["ok"] or retry.result["outcome"] == "NO_CANDIDATES"
        failure = attempts[-1].result["outcome"] if failed else None
        change = failed and action != "skip_task"
        run.emit("worker.decision", task_id=task.task_id, action=action, llm_called=llm_called,
                 retried=len(attempts) > 1, request_plan_change=change, outcome=failure)
        return WorkResult(task, attempts, failure, change, llm_error)

    @staticmethod
    def valid_input(task):
        days = task.arguments.days
        return bool(task.arguments.url and (
            type(days) is int and 1 <= days <= 30 if task.tool == "urlscan_history" else days is None
        ))

    @staticmethod
    def retry_days(task, outcome):
        if (outcome not in RECOVERABLE or task.tool != "urlscan_history"
                or "days" in task.fixed_arguments or not task.arguments.url):
            return None
        days = task.arguments.days
        if days is None or not 1 <= days <= 30:
            return None
        if outcome in {"NO_CANDIDATES", "NO_RECORD"}:
            return 14 if days < 14 else 30 if days < 30 else None
        return 1 if days > 1 else None

    @staticmethod
    def _attempt(task, arguments, number, invoke_tool, run):
        run.emit("worker.attempt", task_id=task.task_id, tool=task.tool,
                 attempt=number, days=arguments.days)
        try:
            result = invoke_tool(task.tool, arguments.as_kwargs(), run)
        except Exception:
            run.emit("error.handled", code="UNEXPECTED_TOOL_ERROR", handling="continue")
            result = {
                "check": task.tool, "outcome": "UNEXPECTED_TOOL_ERROR", "ok": False,
                "data": None, "error": {"code": "UNEXPECTED_TOOL_ERROR", "http_status": None},
            }
        return Attempt(task.run_id, task.task_id, task.tool, arguments, number, result)

    @staticmethod
    def _choose(decider, task, outcome, days, run):
        try:
            choices = decider.choose(
                "worker_recovery", "Pick exactly one action. Retry only the same lookup with the offered period.",
                {"tool": task.tool, "outcome": outcome, "days": task.arguments.days, "retry_days": days},
                [
                    function("retry_same_tool", "Retry with the offered lookback only."),
                    function("skip_task", "Keep the failure and skip further recovery for this task."),
                    function("request_new_plan", "Send the failure to Planner for a different lookup."),
                ],
            )
            if len(choices) == 1 and choices[0][0] in WORKER_ACTIONS and choices[0][1] == {}:
                return choices[0][0], None
            raise DecisionError("LLM_REJECTED_CHOICE")
        except DecisionError as error:
            run.emit("error.handled", code=str(error), handling="rules_fallback")
            return "request_new_plan", str(error)
