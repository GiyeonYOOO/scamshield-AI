"""Rule-first verification for F3021 handoffs."""

from .llm import DecisionError, function
from .work import ValidationResult, WorkerAgent


def repeated_call(signature, seen):
    previous = signature in seen
    seen.add(signature)
    return previous


def changed_fixed_arguments(expected, actual, fixed):
    return any(expected.get(key) != actual.get(key) for key in fixed)


def verify_execution(plan, work, events, previous_calls, max_replans, run, decider=None):
    problems = set()
    actual = tuple(w.task for w in work)
    if actual != plan.tasks:
        problems.add("PLAN_ORDER")
    if plan.revision > max_replans:
        problems.add("REPLAN_LIMIT")

    attempted = []
    declared = []
    reported = []
    seen = set(previous_calls)
    tasks = {task.task_id: task for task in plan.tasks}
    planned_tools = {task.tool for task in plan.tasks}
    for entry in work:
        task = tasks.get(entry.task.task_id)
        if task is None or task.tool != entry.task.tool or task.run_id != plan.run_id:
            problems.add("UNPLANNED_TOOL")
            continue
        if not entry.attempts and (entry.failure_code != "INVALID_INPUT" or WorkerAgent.valid_input(task)):
            problems.add("MISSING_OR_EXTRA_ATTEMPT")
        if len(entry.attempts) > 1 + WorkerAgent.max_retries:
            problems.add("RETRY_LIMIT")
        for index, attempt in enumerate(entry.attempts, 1):
            attempted.append((attempt.tool, attempt.arguments.days))
            reported.append((attempt.tool, attempt.result["outcome"], attempt.result["ok"]))
            declared.append((attempt.task_id, attempt.tool, attempt.number, attempt.arguments.days))
            if (attempt.tool != task.tool or attempt.run_id != plan.run_id
                    or attempt.task_id != task.task_id):
                problems.add("UNPLANNED_TOOL")
            if changed_fixed_arguments(task.arguments.as_kwargs(), attempt.arguments.as_kwargs(), task.fixed_arguments):
                problems.add("FIXED_ARGUMENT_CHANGED")
            expected_days = (task.arguments.days if index == 1 else
                             WorkerAgent.retry_days(task, entry.attempts[0].result["outcome"]))
            if attempt.number != index or attempt.arguments.days != expected_days or (index > 1 and expected_days is None):
                problems.add("UNDECLARED_RETRY")
            signature = (attempt.tool, attempt.arguments)
            if repeated_call(signature, seen):
                problems.add("DUPLICATE_CALL")

    observed = [(event.data.get("tool"), event.data.get("days")) for event in events
                if event.event_type == "tool.requested"]
    observed_declarations = [
        tuple(event.data.get(key) for key in ("task_id", "tool", "attempt", "days"))
        for event in events if event.event_type == "worker.attempt"
    ]
    observed_results = [
        tuple(event.data.get(key) for key in ("tool", "outcome", "ok"))
        for event in events if event.event_type == "tool.finished"
    ]
    if any(name not in planned_tools for name, _ in observed):
        problems.add("UNPLANNED_TOOL")
    if attempted != observed or declared != observed_declarations or reported != observed_results:
        problems.add("MISSING_OR_EXTRA_ATTEMPT")
    if problems:
        result = ValidationResult("anomaly", tuple(sorted(problems)), (), True)
        called = False
    else:
        # A partial report has some data but no complete verification. The model
        # can advise whether another source is helpful, never certify the report.
        incomplete = any(entry.failure_code == "INCOMPLETE_REPORT"
                         and entry.attempts and entry.attempts[-1].result.get("data")
                         for entry in work)
        called = incomplete and decider is not None
        change, error = _review_partial_report(decider, run) if called else (incomplete, None)
        result = ValidationResult("needs_review" if incomplete else "verified",
                                  ("INCOMPLETE_REPORT",) if incomplete else (), work, change, error)
    for code in result.codes or (None,):
        run.emit("audit.checked", status=result.status, code=code,
                 request_plan_change=result.request_plan_change, llm_called=called, revision=plan.revision)
    return result


def _review_partial_report(decider, run):
    try:
        choices = decider.choose(
            "log_review",
            "Recommend another source or keep a partial report for manual review. Do not certify evidence.",
            {"outcome": "INCOMPLETE_REPORT"},
            [
                function("request_independent_source", "Seek a different source for missing evidence."),
                function("keep_for_manual_review", "Keep the report marked incomplete."),
            ],
        )
        if choices == [("keep_for_manual_review", {})]:
            return False, None
        if choices == [("request_independent_source", {})]:
            return True, None
        raise DecisionError("LLM_REJECTED_CHOICE")
    except DecisionError as error:
        run.emit("error.handled", code=str(error), handling="rules_fallback")
        return True, str(error)
