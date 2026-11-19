"""F3005–F3012: graph execution, session memory and event publication."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from time import perf_counter
from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from langsmith import tracing_context

from .assessment import DEFAULT_FRESHNESS_HOURS, assess, final_response
from .events import EventBus, RunEvents, session_reference
from .llm import (
    DecisionError, OpenAICompatibleDecider, function, intent_context, lookup_functions,
    valid_lookup_arguments,
)
from .plan_models import AnalysisPlanDraft, TARGET_TYPES, TargetType
from .request import analyze_request, exclusive_provider
from .tools import ToolResult, build_tools
from .work import PlanBatch, ToolArguments, ValidationResult, WorkerAgent


INITIAL_TOOLS = ("google_safe_browsing", "virustotal_url")
PROVIDER_TOOLS = {
    "google": ("google_safe_browsing",),
    "virustotal": ("virustotal_url", "virustotal_domain"),
    "urlscan": ("urlscan_history",),
}
PERMANENT_ERRORS = {"AUTH_ERROR", "MISSING_KEY", "INVALID_INPUT"}
DEFAULT_DECIDER = object()
SIMPLE_CHAT = {"안녕", "안녕하세요", "반갑습니다", "감사합니다", "고마워요", "hello", "hi"}


class AgentState(TypedDict, total=False):
    text: str
    target_type: TargetType
    memory: dict
    message_context_cache: dict
    context_analysis: bool
    context_text: str | None
    request: dict
    pending: list[str]
    results: dict[str, ToolResult]
    assessment: dict
    replans: int
    stop_reason: str
    response: dict
    decisions: list[dict]
    llm_error: str
    model_plan: list[str]
    run: RunEvents
    provider_limit: tuple[str, ...]
    batch: PlanBatch
    verification: ValidationResult
    attempted_calls: set[tuple[str, ToolArguments]]
    attempted_tool_names: set[str]
    replan_reason: str


@dataclass
class Conversation:
    memory: dict = field(default_factory=dict)
    message_context_cache: dict = field(default_factory=dict, repr=False)
    lock: Lock = field(default_factory=Lock)


class ScamshieldAgent:
    """Invoke one process-local conversation turn by session ID."""

    def __init__(self, *, max_replans=2, clock=None, decider=DEFAULT_DECIDER,
                 event_bus: EventBus | None = None):
        if type(max_replans) is not int or not 0 <= max_replans <= 2:
            raise ValueError("max_replans must be an integer between 0 and 2")
        self.max_replans = max_replans
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.tools = build_tools()
        self.event_bus = event_bus if event_bus is not None else EventBus()
        self.model_setup_error = None
        try:
            self.decider = OpenAICompatibleDecider.from_env() if decider is DEFAULT_DECIDER else decider
        except (DecisionError, ValueError):
            self.decider = None
            self.model_setup_error = "INVALID_LLM_ENDPOINT"
        self.sessions: dict[str, Conversation] = {}
        self.sessions_lock = Lock()

        graph = StateGraph(AgentState)
        for name, node in (
            ("analyze", self._analyze), ("plan", self._plan), ("execute", self._execute),
            ("judge", self._judge), ("replan", self._replan), ("respond", self._respond),
        ):
            graph.add_node(name, self._instrument_node(name, node))
        graph.add_edge(START, "analyze")
        graph.add_conditional_edges(
            "analyze", lambda state: state["request"]["kind"] == "analysis",
            {True: "plan", False: "respond"},
        )
        graph.add_edge("plan", "execute")
        graph.add_edge("execute", "judge")
        graph.add_conditional_edges(
            "judge", lambda state: not state["stop_reason"],
            {True: "replan", False: "respond"},
        )
        graph.add_conditional_edges(
            "replan", lambda state: not state["stop_reason"],
            {True: "execute", False: "respond"},
        )
        graph.add_edge("respond", END)
        self.graph = graph.compile()

    @staticmethod
    def _instrument_node(name, node):
        def execute(state: AgentState):
            run = state["run"]
            run.emit("node.entered", node=name)
            status = "failed"
            try:
                update = node(state)
                status = "completed"
                return update
            except Exception:
                run.emit("error.handled", code="UNEXPECTED_NODE_ERROR", handling="propagated")
                raise
            finally:
                run.emit("node.finished", node=name, status=status)
        return execute

    def invoke_for_plan(
        self, text: str, *, session_id: str, target_type: TargetType = "url", context_analysis: bool = False,
        context_text: str | None = None,
    ) -> tuple[dict, AnalysisPlanDraft | None]:
        """Run one turn and return a draft for explicit storage by trusted application code."""
        if target_type not in TARGET_TYPES:
            raise ValueError("invalid target_type")
        response = self.invoke(text, session_id=session_id, target_type=target_type,
                               context_analysis=context_analysis, context_text=context_text)
        draft = None
        has_analysis = "conditions" in response or (
            target_type == "text" and response["status"] == "SUSPICIOUS"
        )
        if has_analysis and response.get("actions"):
            draft = AnalysisPlanDraft(
                owner_reference=session_reference(session_id), analysis_id=response["run_id"],
                target_type=target_type, actions=tuple(response["actions"]),
            )
        return response, draft

    def invoke(self, text: str, *, session_id: str, target_type: TargetType = "url", context_analysis: bool = False,
               context_text: str | None = None) -> dict:
        if not session_id.strip():
            raise ValueError("session_id is required")
        if target_type not in TARGET_TYPES:
            raise ValueError("invalid target_type")
        with self.sessions_lock:
            if session_id not in self.sessions:
                self.sessions[session_id] = Conversation()
            session = self.sessions[session_id]
        with session.lock, tracing_context(enabled=False):
            run = RunEvents(self.event_bus, session_reference(session_id))
            status, replans = "failed", None
            run.emit("run.started", max_replans=self.max_replans)
            try:
                if self.model_setup_error:
                    run.emit("error.handled", code=self.model_setup_error, handling="rules_fallback")
                state = self.graph.invoke({
                    "text": text, "memory": session.memory, "results": {}, "replans": 0,
                    "decisions": [], "llm_error": self.model_setup_error, "run": run,
                    "target_type": target_type,
                    "message_context_cache": session.message_context_cache,
                    "context_analysis": context_analysis,
                    "context_text": context_text,
                })
                if state["request"]["kind"] == "analysis":
                    request = state["request"]
                    session.memory = {
                        "url": request["url"], "conditions": dict(request["conditions"]),
                        "signals": list(request["signals"]),
                    }
                status, replans = "completed", state["replans"]
                state["response"]["run_id"] = run.run_id
                return state["response"]
            except Exception:
                run.emit("error.handled", code="UNEXPECTED_RUN_ERROR", handling="propagated")
                raise
            finally:
                run.emit("run.finished", status=status, replans=replans)

    def _choose(self, state, stage, instructions, context, functions, validate):
        if self.decider is None or state.get("llm_error"):
            return None, {}
        try:
            choices = self.decider.choose(stage, instructions, context, functions)
            if not validate(choices):
                raise DecisionError("LLM_REJECTED_CHOICE")
        except DecisionError as error:
            state["run"].emit("error.handled", code=str(error), handling="rules_fallback")
            return None, {
                "llm_error": str(error),
                "decisions": [*state["decisions"], {"stage": stage, "source": "rules", "fallback": str(error)}],
            }
        for name, arguments in choices:
            state["run"].emit(
                "llm.decision", stage=stage, choice=name, reason=arguments.get("reason_code"),
            )
        return choices, {
            "decisions": [*state["decisions"], {
                "stage": stage, "source": "llm", "choices": [name for name, _ in choices],
            }],
        }

    def _analyze(self, state):
        text, memory = state["text"], state["memory"]
        target_type = state.get("target_type", "url")
        request = analyze_request(text, memory, target_type=target_type)
        update = {"request": request}
        if request["kind"] == "text_only" or text.strip().rstrip(".!~ ").lower() in SIMPLE_CHAT:
            return update
        if request.get("issue") in {"INVALID_OR_SENSITIVE_URL", "MULTIPLE_URLS", "INVALID_PERIOD"}:
            return update
        names = list(self.tools) if request["kind"] == "analysis" else []
        provider = exclusive_provider(text) if names and target_type != "text" else None
        if provider:
            update["provider_limit"] = PROVIDER_TOOLS[provider]
            names = [name for name in names if name in update["provider_limit"]]
        if request.get("conditions", {}).get("exact_only") and "virustotal_domain" in names:
            names.remove("virustotal_domain")
        non_lookup = {"general_conversation"} if target_type != "text" else set()
        if not names:
            non_lookup.add("ask_for_public_url")
        if not names and memory.get("url"):
            non_lookup.add("use_previous_url")

        def validate(choices):
            selected = [name for name, _ in choices]
            return (
                all(valid_lookup_arguments(name, arguments) for name, arguments in choices)
                and (
                    (len(selected) == 1 and selected[0] in non_lookup)
                    or (1 <= len(selected) <= 2 and len(set(selected)) == len(selected)
                        and set(selected).issubset(names))
                )
            )

        options = lookup_functions(names, self.tools)
        if "general_conversation" in non_lookup:
            options.append(function(
                "general_conversation", "The user is greeting us or asking about the service, not requesting a lookup.",
            ))
        if "ask_for_public_url" in non_lookup:
            options.append(function("ask_for_public_url", "A security lookup is requested but a usable target is missing."))
        if "use_previous_url" in non_lookup:
            options.append(function("use_previous_url", "The user explicitly refers to the last checked link."))
        choices, metadata = self._choose(
            state, "intent_and_plan",
            "Infer intent and pick one or two necessary lookups in execution order. "
            "An explicit restriction to a single provider takes precedence over the default plan. "
            "If the request says to use only one provider, call only its matching function. "
            "When user text is withheld and a validated target plus local risk signals are present, "
            "choose relevant lookups using the provided labels. "
            "For each lookup, provide an applicable reason_code when possible. "
            "For a bare URL or general safety check, prefer Google followed by VirusTotal URL. "
            "For a specific request (e.g. public scan history), choose only the relevant lookups. "
            "Use conversation functions only when lookup is unnecessary or the target is missing.",
            intent_context(text, request, bool(memory.get("url")), target_type=target_type), options, validate,
        )
        update.update(metadata)
        if not choices:
            return update
        selected = [name for name, _ in choices]
        if selected == ["general_conversation"]:
            update["request"] = {"kind": "chat", "signals": request["signals"]}
        elif selected == ["ask_for_public_url"]:
            update["request"] = {"kind": "clarify", "issue": "URL_REQUIRED", "signals": request["signals"]}
        elif selected == ["use_previous_url"]:
            update["request"] = analyze_request(f"같은 링크 {text}", memory)
        else:
            update["pending"] = selected
            update["model_plan"] = selected
        return update

    @staticmethod
    def _plan(state):
        if state.get("pending"):
            return {"pending": state["pending"]}
        limit = state.get("provider_limit")
        selected = [limit[0]] if limit else list(INITIAL_TOOLS)
        return {
            "pending": selected,
            "decisions": [*state["decisions"], {
                "stage": "plan", "source": "rules", "choices": selected,
            }],
        }

    def _execute(self, state):
        request = state["request"]
        results = dict(state["results"])
        for name in state["pending"]:
            if name in results:
                continue
            arguments = {"url": request["url"]}
            if name == "urlscan_history":
                hours = request["conditions"].get("max_age_hours", DEFAULT_FRESHNESS_HOURS)
                arguments["days"] = (hours + 23) // 24
            results[name] = self._call_tool(name, arguments, state["run"])
        return {"results": results}

    def _call_tool(self, name, arguments, run):
        run.emit("tool.requested", tool=name, days=arguments.get("days"), input_url=arguments.get("url"),
                 target_scope="host" if name in {"urlscan_history", "virustotal_domain"} else "url")
        started = perf_counter()
        try:
            result = self.tools[name].invoke(arguments)
        except Exception:
            run.emit("tool.finished", tool=name, outcome="UNEXPECTED_TOOL_ERROR", ok=False,
                     duration_ms=round((perf_counter() - started) * 1000))
            raise
        run.emit("tool.finished", tool=name, outcome=result["outcome"], ok=result["ok"],
                 duration_ms=round((perf_counter() - started) * 1000))
        if not result["ok"]:
            run.emit("error.handled", code=result["outcome"], handling="continue")
        return result

    def _judge(self, state):
        results = state["results"]
        request = state["request"]
        assessment = assess(request, results, self.clock())
        alternatives = ["urlscan_history"]
        if not request["conditions"].get("exact_only"):
            alternatives.append("virustotal_domain")
        if self.decider is not None:
            alternatives.extend(INITIAL_TOOLS)
        limit = state.get("provider_limit")
        attempted = state.get("attempted_tool_names", ())
        remaining = [name for name in alternatives if name not in results and name not in attempted
                     and (not limit or name in limit)]

        direct_google = results.get("google_safe_browsing", {}).get("ok", False)
        direct_vt = any(
            item["tool"] == "virustotal_url" and item["freshness_met"]
            and item["outcome"] == "REPORT" for item in assessment["evidence"]
        )
        model_plan = state.get("model_plan") or [name for name in (limit or ()) if name in results]
        planned_evidence_ready = bool(model_plan) and all(
            any(
                item["tool"] == name and item["eligible"]
                and item["outcome"] in {"MATCH", "NO_MATCH", "REPORT", "CANDIDATES"}
                for item in assessment["evidence"]
            )
            for name in model_plan
        )
        if any(result["outcome"] in PERMANENT_ERRORS for result in results.values()):
            stop_reason = "UNAVAILABLE_CONFIGURATION"
        elif not state.get("replan_reason") and assessment["constraints_met"] and (
            assessment["known"] or planned_evidence_ready or (direct_google and direct_vt) or (
                assessment["dated_evidence"] and "urlscan_history" in results
            )
        ):
            stop_reason = "EVIDENCE_COLLECTED"
        elif not remaining:
            stop_reason = "NO_MORE_ALTERNATIVES"
        elif state["replans"] >= self.max_replans:
            stop_reason = "REPLAN_LIMIT"
        else:
            stop_reason = ""
        if stop_reason:
            state["run"].emit("replan.decided", performed=False, reason=stop_reason,
                              count=state["replans"], source="rules")
        return {"assessment": assessment, "pending": remaining, "stop_reason": stop_reason}

    def _replan(self, state):
        remaining = state["pending"]
        choices, metadata = self._choose(
            state, "replan",
            "Choose one unused lookup that can help with the unresolved condition. "
            "Provide an applicable reason_code when choosing a lookup. "
            "If no option can address the missing evidence, choose finish_without_lookup.",
            {
                "conditions": state["request"]["conditions"],
                "replan_reason": state.get("replan_reason"),
                "constraints_met": state["assessment"]["constraints_met"],
                "outcomes": {name: result["outcome"] for name, result in state["results"].items()},
                "observations": [
                    {key: item[key] for key in ("tool", "scope", "freshness_met")}
                    for item in state["assessment"]["evidence"]
                ],
            },
            [*lookup_functions(remaining, self.tools),
             function("finish_without_lookup", "No unused lookup can improve the evidence.")],
            lambda calls: len(calls) == 1 and valid_lookup_arguments(*calls[0])
            and calls[0][0] in {*remaining, "finish_without_lookup"},
        )
        if choices and choices[0][0] == "finish_without_lookup":
            state["run"].emit("replan.decided", performed=False, reason="LLM_NO_USEFUL_ALTERNATIVE",
                              count=state["replans"], source="llm")
            return {"stop_reason": "LLM_NO_USEFUL_ALTERNATIVE", **metadata}
        name = choices[0][0] if choices else remaining[0]
        if not choices:
            metadata["decisions"] = [*metadata.get("decisions", state["decisions"]), {
                "stage": "replan", "source": "rules", "choices": [name],
            }]
        count = state["replans"] + 1
        reason = state.get("replan_reason") or (
            "COVERAGE_INCOMPLETE" if state["assessment"]["constraints_met"] else "CONSTRAINTS_UNMET"
        )
        state["run"].emit("replan.decided", performed=True, reason=reason, tool=name, count=count,
                          source="llm" if choices else "rules")
        return {"pending": [name], "replans": count, **metadata}

    def _respond(self, state):
        response = final_response(
            state["request"], state.get("assessment"), state["results"],
            state["replans"], state.get("stop_reason"),
        )
        if state.get("target_type") == "text":
            response["text_assessment"] = {
                "status": "signals_found" if state["request"]["signals"] else "no_signals_found",
                "url_lookup": "attempted" if state["results"] else "not_attempted",
            }
        if state.get("context_analysis") and state.get("target_type") in {"url", "text"}:
            note = state["context_text"]
            context = WorkerAgent.interpret_message(
                note if note is not None else state["text"],
                self.decider, state["message_context_cache"], state["run"],
            )
            if "text_assessment" in response:
                response["text_assessment"]["context"] = context
            else:
                response["message_context"] = context
        metadata = {}
        if state["request"]["kind"] == "analysis" and any(item["eligible"] for item in response["evidence"]):
            actions = response["actions"]
            choices, metadata = self._choose(
                state, "response",
                "Choose the most helpful approved preventive action to show first, and "
                "highlight one evidence entry that directly supports the fixed decision.",
                {"status": response["status"], "conditions": response["conditions"],
                 "actions": actions, "local_signals": response["local_signals"],
                 "observations": [
                     {key: item[key] for key in ("source", "outcome", "scope", "eligible", "signal")}
                     for item in response["evidence"]
                 ]},
                [function("prioritize_action", "Choose which verified observation and approved action to emphasize.", {
                    "index": {"type": "integer", "enum": list(range(len(actions)))},
                    "evidence_index": {"type": "integer", "enum": list(range(len(response["evidence"])))},
                })],
                lambda calls: self._valid_response_choice(calls, response),
            )
            if choices:
                selection = choices[0][1]
                index = selection["index"]
                response["actions"] = [actions[index], *actions[:index], *actions[index + 1:]]
                item = response["evidence"][selection["evidence_index"]]
                response["highlighted_evidence"] = item
        response["decisions"] = metadata.get("decisions", state["decisions"])
        response["assessment_source"] = "rules"
        error = metadata.get("llm_error", state.get("llm_error"))
        if error:
            response["llm_error"] = error
        state["run"].emit("response.generated", status=response["status"])
        return {"response": response, **metadata}

    @staticmethod
    def _valid_response_choice(calls, response):
        if len(calls) != 1 or calls[0][0] != "prioritize_action":
            return False
        args = calls[0][1]
        if not isinstance(args, dict) or set(args) != {"index", "evidence_index"}:
            return False
        return (
            type(args["index"]) is int and 0 <= args["index"] < len(response["actions"])
            and type(args["evidence_index"]) is int
            and 0 <= args["evidence_index"] < len(response["evidence"])
        )
