"""F3020: evaluate immutable events and diagnose only positive findings."""

from .execution_audit import changed_fixed_arguments, repeated_call
from .llm import DecisionError, function


RULES = {
    "DUPLICATE_CALL": ("동일 Tool과 동일 조회 인자로 반복 호출했습니다", "실행 전 이전 호출 결과를 재사용하도록 점검하세요"),
    "REPLAN_LIMIT": ("기록된 재계획이 설정된 상한을 넘었습니다", "재계획 횟수를 증가시키는 지점과 종료 조건을 점검하세요"),
    "UNPLANNED_TOOL": ("Planner가 배정하지 않은 Tool 호출이 확인됐습니다", "Worker가 현재 작업 목록의 Tool만 실행하도록 점검하세요"),
    "FIXED_ARGUMENT_CHANGED": ("Planner가 고정한 URL 또는 조회 일수가 변경됐습니다", "재시도에서 고정 인자를 복사하고 가변 인자만 변경하세요"),
    "MISSING_OR_EXTRA_ATTEMPT": ("계획·시도·결과 중 일치하지 않는 실행 기록이 있습니다", "작업별 호출과 결과를 일대일로 전달하는지 점검하세요"),
    "RETRY_LIMIT": ("동일 작업의 재시도가 상한을 넘었습니다", "Worker가 재시도 상한 이후 문제를 Planner에 전달하도록 점검하세요"),
    "PLAN_ORDER": ("Planner 작업 목록과 보고된 작업 순서가 일치하지 않습니다", "작업 ID와 처리 순서를 대조하세요"),
    "UNDECLARED_RETRY": ("재시도 순번이나 변경 인자가 허용된 규칙을 벗어났습니다", "Worker 재시도 인자와 순번을 점검하세요"),
}


def evaluate_events(events, run_id):
    findings = {}
    plans = {}
    audited = set()
    revision = 0
    declaration = None
    previous = {}
    seen = set()
    replans = []
    pending_requests = {}
    uncertain = False
    start = next((row for row in events if row["event_type"] == "run.started"), None)
    cap = start["data"].get("max_replans") if start else None
    finished = bool(events and events[-1]["event_type"] == "run.finished")

    def warn(code, sequence, *related):
        key = (code, revision)
        entry = findings.setdefault(key, {
            "code": code, "location": {"revision": revision, "sequence": sequence},
            "reason": RULES[code][0], "evidence_event_ids": set(),
        })
        entry["evidence_event_ids"].update([sequence, *related])

    for row in events:
        kind, data, seq = row["event_type"], row["data"], row["sequence"]
        if kind == "planner.task":
            revision = data.get("revision", revision)
            if "task_id" in data:
                plans.setdefault(revision, {})[data["task_id"]] = row
            else:
                uncertain = True
        elif kind == "worker.attempt":
            if declaration is not None:
                uncertain = True
            declaration = row
        elif kind == "tool.requested":
            tool = data.get("tool")
            signature = (tool, data.get("input_ref"), data.get("days"))
            if not tool or not data.get("input_ref"):
                uncertain = True
            elif repeated_call(signature, seen):
                warn("DUPLICATE_CALL", seq, previous[signature])
            else:
                previous[signature] = seq
            pending_requests.setdefault(tool, []).append(seq)
            if revision in plans:
                tasks = plans[revision]
                task = tasks.get(declaration["data"].get("task_id")) if declaration else None
                if tool and tool not in {item["data"].get("tool") for item in tasks.values()}:
                    warn("UNPLANNED_TOOL", seq, *(item["sequence"] for item in tasks.values()))
                elif task is not None:
                    expected = task["data"]
                    if expected.get("tool") != tool and tool:
                        warn("UNPLANNED_TOOL", seq, task["sequence"], declaration["sequence"])
                    fixed = []
                    if expected.get("fixed_url") and expected.get("input_ref") and data.get("input_ref"):
                        fixed.append("input_ref")
                    elif expected.get("fixed_url"):
                        uncertain = True
                    if expected.get("fixed_days") and "days" in expected and "days" in data:
                        fixed.append("days")
                    elif expected.get("fixed_days"):
                        uncertain = True
                    if changed_fixed_arguments(expected, data, fixed):
                        warn("FIXED_ARGUMENT_CHANGED", seq, task["sequence"], declaration["sequence"])
            declaration = None
        elif kind == "tool.finished":
            if "outcome" not in data or type(data.get("ok")) is not bool:
                uncertain = True
            calls = pending_requests.get(data.get("tool"), [])
            if calls:
                calls.pop(0)
            else:
                uncertain = True
        elif kind == "replan.decided" and data.get("performed"):
            replans.append(seq)
            if type(cap) is int and (len(replans) > cap or data.get("count", 0) > cap):
                warn("REPLAN_LIMIT", seq, start["sequence"], *replans[:-1])
        elif kind == "audit.checked":
            audit_revision = data.get("revision", revision)
            audited.add(audit_revision)
            code = data.get("code")
            if data.get("status") == "anomaly" and code in RULES:
                tasks = plans.get(audit_revision, {})
                # Include the underlying batch span, not only the derived rule event.
                begin = min((item["sequence"] for item in tasks.values()), default=seq)
                relevant = [item["sequence"] for item in events
                            if begin <= item["sequence"] < seq and item["event_type"] in {
                                "planner.task", "worker.attempt", "tool.requested", "tool.finished",
                            }]
                warn(code, seq, *relevant)
    missing = (
        not finished or not start or not any(row["event_type"] == "response.generated" for row in events)
        or events[-1]["data"].get("status") != "completed"
        or [row["sequence"] for row in events] != list(range(1, len(events) + 1))
        or type(cap) is not int or uncertain or declaration is not None or any(pending_requests.values())
        or bool(set(plans) - audited)
        or bool(seen and not plans)
        or bool(not plans and any(row["event_type"] == "node.entered" and row["data"].get("node") == "plan"
                                  for row in events))
    )
    warnings = sorted(findings.values(), key=lambda item: (item["location"]["sequence"], item["code"]))
    for entry in warnings:
        entry["evidence_event_ids"] = [f"{run_id}:{seq}" for seq in sorted(entry["evidence_event_ids"])]
    return {
        "status": "warning" if warnings else "inconclusive" if missing else "normal",
        "warnings": warnings, "complete": not missing,
        "reason": "INSUFFICIENT_EVENTS" if missing else None,
    }


def diagnose(decider, warnings):
    codes = sorted({entry["code"] for entry in warnings})
    choices = decider.choose(
        "log_diagnosis",
        "Choose the likely responsible component and the best supported warning for remediation. "
        "Use only the supplied codes. This is a diagnosis, never an instruction to replan.",
        {"warnings": [{"code": item["code"], "sequence": item["location"]["sequence"]}
                      for item in warnings]},
        [function("diagnose_warning", "Select a grounded cause and remediation.", {
            "component": {"type": "string", "enum": ["Planner", "Worker", "Tool"]},
            "evidence_code": {"type": "string", "enum": codes},
        })],
    )
    if len(choices) != 1 or choices[0][0] != "diagnose_warning":
        raise DecisionError("LLM_REJECTED_CHOICE")
    args = choices[0][1]
    if (
        not isinstance(args, dict) or set(args) != {"component", "evidence_code"}
        or args["component"] not in ("Planner", "Worker", "Tool") or args["evidence_code"] not in codes
    ):
        raise DecisionError("LLM_REJECTED_CHOICE")
    warning = next(item for item in warnings if item["code"] == args["evidence_code"])
    component = args["component"]
    reason, repair = RULES[warning["code"]]
    return {
        "component": component, "evidence_code": warning["code"],
        "evidence_event_ids": warning["evidence_event_ids"],
        "text": f"{component} 단계의 문제 가능성이 있습니다. 실행 기록에서 {reason}. {repair}.",
    }
