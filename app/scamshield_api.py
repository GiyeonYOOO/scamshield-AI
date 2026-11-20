"""F3017: standalone SCAMSHIELD API over existing Agent and SQLite services."""

from contextlib import ExitStack, asynccontextmanager
import os
from pathlib import Path
import re
import sqlite3
from typing import Annotated

from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import APIKeyCookie
from starlette.exceptions import HTTPException

from .scamshield import ScamshieldAgent
from .scamshield.api_models import (
    Analysis, ChatRequest, ChatResponse, ErrorResponse, FollowUpAnswer, FollowUpResponse,
    Identifier, LogDetail, LogEvaluation, LogSummary,
    PlanCreate, PlanDraftResponse, PlanPatch, PlanResponse, PlanSaved,
)
from .scamshield.api_sessions import BrowserSessions, COOKIE_NAME, PlanDrafts, SESSION_SECONDS
from .scamshield.events import EventBus
from .scamshield.execution_logs import ExecutionLogs, LoggingAgent
from .scamshield.follow_up import FollowUpSessions
from .scamshield.message_context import safe_message
from .scamshield.planner import PlannerAgent
from .scamshield.prevention_plans import PreventionPlans
from .scamshield.request import URL


DEFAULT_DB = Path(__file__).resolve().parents[1] / "scamshield.sqlite3"
FRONTEND = Path(__file__).resolve().parents[1] / "frontend"


class ApiError(Exception):
    def __init__(self, status, code, message):
        self.status = status
        self.code = code
        self.message = message


def error_response(status, code, message, *, headers=None):
    return JSONResponse(
        status_code=status, content={"error": {"code": code, "message": message}},
        headers={"Cache-Control": "no-store", **(headers or {})},
    )


session_cookie = APIKeyCookie(name=COOKIE_NAME, auto_error=False)


def required_owner(request: Request, token: Annotated[str | None, Depends(session_cookie)]) -> str:
    owner = request.app.state.sessions.resolve(token)
    if owner is None:
        raise ApiError(401, "SESSION_REQUIRED", "유효한 세션이 필요합니다. 먼저 분석 요청으로 세션을 시작하세요.")
    return owner


Owner = Annotated[str, Depends(required_owner)]


def set_session_cookie(response: Response, token: str, secure: bool):
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_SECONDS, path="/api",
                        secure=secure, httponly=True, samesite="strict")


def missing_plan():
    return ApiError(404, "PLAN_NOT_FOUND", "예방 계획을 찾을 수 없습니다.")


def missing_log():
    return ApiError(404, "LOG_NOT_FOUND", "실행 로그를 찾을 수 없습니다.")


def invalid_schedule():
    return ApiError(422, "INVALID_SCHEDULE", "날짜가 유효하고 같은 날 종료 시각이 시작 시각보다 늦어야 합니다.")


ERRORS = {
    401: {"model": ErrorResponse, "description": "세션이 없거나 만료됨"},
    403: {"model": ErrorResponse, "description": "허용되지 않은 출처"},
    404: {"model": ErrorResponse, "description": "현재 세션에서 항목을 찾을 수 없음"},
    422: {"model": ErrorResponse, "description": "요청 형식 또는 값이 올바르지 않음"},
    500: {"model": ErrorResponse, "description": "서버 내부 오류"},
    503: {"model": ErrorResponse, "description": "저장 서비스 일시 이용 불가"},
}


def create_app(*, db_path=None, secure_cookies=None, agent_factory=None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        path = db_path if db_path is not None else Path(os.getenv("SCAMSHIELD_DB_PATH") or DEFAULT_DB)
        with ExitStack() as stack:
            app.state.logs = ExecutionLogs(path)
            stack.callback(app.state.logs.close)
            app.state.plans = PreventionPlans(path)
            stack.callback(app.state.plans.close)
            app.state.sessions = BrowserSessions(path)
            stack.callback(app.state.sessions.close)
            app.state.drafts = PlanDrafts()
            app.state.follow_ups = FollowUpSessions()
            bus = EventBus()
            logger = LoggingAgent(app.state.logs)
            app.state.logging_agent = logger
            bus.subscribe(logger.record)
            if agent_factory is not None:
                app.state.agent = agent_factory(event_bus=bus)
            elif os.getenv("SCAMSHIELD_AGENT_MODE", "multi") == "single":
                app.state.agent = ScamshieldAgent(event_bus=bus)
            else:
                app.state.agent = PlannerAgent(
                    event_bus=bus, logging_agent=logger,
                    enable_worker_llm=os.getenv("SCAMSHIELD_WORKER_LLM", "1") != "0",
                )
            bus.subscribe(lambda event: logger.evaluate_completed(event, getattr(app.state.agent, "decider", None)))
            app.state.secure_cookies = (
                secure_cookies if secure_cookies is not None
                else os.getenv("SCAMSHIELD_SECURE_COOKIES", "1") != "0"
            )
            yield

    application = FastAPI(
        title="SCAMSHIELD AI", description="디지털 사기 예방 분석, 예방 계획 및 실행 로그 API입니다.",
        version="1.0.0", lifespan=lifespan,
    )

    @application.middleware("http")
    async def api_security(request: Request, call_next):
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        origin = request.headers.get("origin")
        expected_origin = f"{request.url.scheme}://{request.url.netloc}"
        if request.method in {"POST", "PATCH", "DELETE"} and origin and origin != expected_origin:
            return error_response(403, "ORIGIN_REJECTED", "이 요청의 출처는 허용되지 않습니다.")
        try:
            response = await call_next(request)
        except Exception:
            return error_response(500, "INTERNAL_ERROR", "요청 처리 중 서버 오류가 발생했습니다.")
        response.headers["Cache-Control"] = "no-store"
        return response

    @application.exception_handler(ApiError)
    async def handle_api_error(request, exc):
        return error_response(exc.status, exc.code, exc.message)

    @application.exception_handler(RequestValidationError)
    async def handle_validation_error(request, exc):
        return error_response(422, "INVALID_REQUEST", "요청 항목의 형식과 필수 값을 확인하세요.")

    @application.exception_handler(HTTPException)
    async def handle_http_error(request, exc):
        known = {404: ("NOT_FOUND", "요청 경로를 찾을 수 없습니다."),
                 405: ("METHOD_NOT_ALLOWED", "이 요청 방식은 지원하지 않습니다.")}
        return error_response(exc.status_code, *known.get(exc.status_code, ("HTTP_ERROR", "요청을 처리할 수 없습니다.")),
                              headers=exc.headers)

    @application.exception_handler(sqlite3.Error)
    async def handle_storage_error(request, exc):
        return error_response(503, "STORAGE_UNAVAILABLE", "저장 서비스를 일시적으로 사용할 수 없습니다.")

    @application.post(
        "/api/chat", response_model=ChatResponse, tags=["분석"], summary="Agent 메시지 분석",
        description="첫 유효 요청에서 세션 쿠키를 발급합니다. 이후 같은 쿠키로 대화를 이어갑니다. 예방 계획은 별도로 저장합니다.",
        responses={
            200: {"content": {"application/json": {"example": {
                "run_id": "0123456789abcdef0123456789abcdef", "status": "completed",
                "analysis": {"status": "GENERAL", "message": "확인할 공개 URL을 알려 주세요."},
                "plan_draft": None,
            }}}},
            **ERRORS,
        },
    )
    def chat(body: ChatRequest, request: Request, response: Response):
        if (body.target_type != "text" and
                re.search(r"\b(?:https?\s*:|[a-z][a-z0-9+.-]*://)", body.message, re.I) and not URL.search(body.message)):
            raise ApiError(422, "INVALID_URL", "인증 정보가 없는 공개 HTTP(S) URL을 입력하세요.")
        state = request.app.state
        cookie = request.cookies.get(COOKIE_NAME)
        if cookie is None:
            token, owner = state.sessions.create()
        else:
            token, owner = None, required_owner(request, cookie)

        call_context = body.call_context if body.target_type == "text" else None
        message = body.message
        if call_context is not None:
            message = safe_message("\n".join(part for part in (message, body.context_note) if part))
        context = {}
        if body.context_analysis and body.target_type in {"url", "text"}:
            context["context_analysis"] = True
            if body.target_type == "url" and body.context_note is not None:
                context["context_text"] = body.context_note
        result, draft = state.agent.invoke_for_plan(message, session_id=owner, target_type=body.target_type, **context)
        if result.get("issue") == "INVALID_OR_SENSITIVE_URL" and body.target_type != "text":
            raise ApiError(422, "INVALID_URL", "인증 정보가 없는 공개 HTTP(S) URL을 입력하세요.")
        if token:
            set_session_cookie(response, token, state.secure_cookies)
        if draft is not None:
            state.drafts.keep(owner, draft)
        return ChatResponse(
            run_id=result["run_id"],
            status="partial" if result.get("llm_error") or result.get("tool_errors") else "completed",
            analysis=Analysis.model_validate(result),
            plan_draft=PlanDraftResponse(analysis_id=draft.analysis_id, target_type=draft.target_type,
                                         actions=list(draft.actions)) if draft is not None else None,
            follow_up=state.follow_ups.start(
                owner, result, body.target_type,
                "\n".join(part for part in (message, context.get("context_text")) if part),
                call_context=call_context.model_dump() if call_context is not None else None,
            ),
        )

    @application.post("/api/chat/{run_id}/follow-up", response_model=FollowUpResponse, tags=["분석"],
                      summary="현재 분석의 확인 질문에 답하거나 건너뛰기", responses=ERRORS)
    def answer_follow_up(run_id: Identifier, body: FollowUpAnswer, request: Request, owner: Owner):
        try:
            return request.app.state.follow_ups.answer(owner, run_id, body.question_id, body.answer)
        except LookupError:
            raise ApiError(404, "FOLLOW_UP_UNAVAILABLE", "이 확인 질문은 만료됐거나 더 이상 열 수 없어요. 필요하면 새로 분석하세요.") from None
        except ValueError:
            raise ApiError(409, "FOLLOW_UP_INVALID_ANSWER", "현재 표시된 질문에서 선택지를 골라 주세요.") from None

    @application.post("/api/plans", response_model=PlanSaved, status_code=201, tags=["예방 계획"],
                      summary="예방 글 작성 또는 현재 세션의 분석 초안 저장", responses=ERRORS)
    def save_plan(body: PlanCreate, request: Request, response: Response,
                  cookie: Annotated[str | None, Depends(session_cookie)]):
        state = request.app.state
        if body.analysis_id is None:
            if cookie is None:
                token, owner = state.sessions.create()
            else:
                token, owner = None, required_owner(request, cookie)
            saved = state.plans.create_post(owner, title=body.title, actions=body.actions)
            if token:
                set_session_cookie(response, token, state.secure_cookies)
            return saved
        owner = required_owner(request, cookie)
        draft = state.drafts.get(owner, body.analysis_id)
        if draft is None:
            raise ApiError(404, "DRAFT_NOT_FOUND", "현재 세션에서 유효한 분석 초안을 찾을 수 없습니다.")
        try:
            return state.plans.save_from_analysis(owner, draft, **body.model_dump(exclude={"analysis_id", "actions"}))
        except ValueError:
            raise invalid_schedule() from None

    @application.get("/api/plans", response_model=list[PlanResponse], tags=["예방 계획"],
                     summary="현재 세션의 예방 계획 목록", responses=ERRORS)
    def list_plans(request: Request, owner: Owner):
        return request.app.state.plans.list_plans(owner)

    @application.get("/api/plans/{plan_id}", response_model=PlanResponse, tags=["예방 계획"],
                     summary="현재 세션의 예방 계획 상세", responses=ERRORS)
    def get_plan(plan_id: Identifier, request: Request, owner: Owner):
        plan = request.app.state.plans.get_plan(owner, plan_id)
        if plan is None:
            raise missing_plan()
        return plan

    @application.patch("/api/plans/{plan_id}", response_model=PlanSaved, tags=["예방 계획"],
                       summary="예방 계획 수정 및 시간 중복 확인", responses=ERRORS)
    def update_plan(plan_id: Identifier, body: PlanPatch, request: Request, owner: Owner):
        try:
            saved = request.app.state.plans.update_plan(owner, plan_id, **body.model_dump(exclude_unset=True))
        except ValueError:
            raise invalid_schedule() from None
        if saved is None:
            raise missing_plan()
        return saved

    @application.delete("/api/plans/{plan_id}", status_code=204, tags=["예방 계획"],
                        summary="현재 세션의 예방 계획 삭제", responses=ERRORS)
    def delete_plan(plan_id: Identifier, request: Request, owner: Owner):
        if not request.app.state.plans.delete_plan(owner, plan_id):
            raise missing_plan()
        return Response(status_code=204)

    @application.get("/api/logs", response_model=list[LogSummary], tags=["실행 로그"],
                     summary="현재 세션의 실행 목록", responses=ERRORS)
    def list_logs(request: Request, owner: Owner):
        return request.app.state.logs.list_runs(owner)

    @application.get("/api/logs/{run_id}", response_model=LogDetail, tags=["실행 로그"],
                     summary="실행 이벤트를 순번대로 조회", responses=ERRORS)
    def get_logs(run_id: Identifier, request: Request, owner: Owner):
        events = request.app.state.logs.get_events(owner, run_id=run_id)
        if not events:
            raise missing_log()
        return {"run_id": run_id, "events": events}

    @application.get("/api/logs/{run_id}/evaluation", response_model=LogEvaluation, tags=["실행 로그"],
                     summary="규칙 기반 이상 징후 및 별도 원인 진단 조회", responses=ERRORS)
    def get_log_evaluation(run_id: Identifier, request: Request, owner: Owner):
        state = request.app.state
        result = state.logs.get_evaluation(owner, run_id)
        if result is None or result["status"] == "inconclusive":
            result = state.logging_agent.evaluate(owner, run_id)
        if result is None:
            raise missing_log()
        return result

    @application.delete("/api/logs/{run_id}", status_code=204, tags=["실행 로그"],
                        summary="현재 세션의 실행 로그 삭제", responses=ERRORS)
    def delete_logs(run_id: Identifier, request: Request, owner: Owner):
        if not request.app.state.logs.delete(owner, run_id=run_id):
            raise missing_log()
        return Response(status_code=204)

    @application.get("/healthz", include_in_schema=False)
    def healthcheck():
        # Lifespan has already opened SQLite and initialized the service.
        return {"status": "ok"}

    @application.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(FRONTEND / "index.html", headers={
            "Content-Security-Policy": (
                "default-src 'self'; base-uri 'none'; object-src 'none'; "
                "style-src 'self' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; "
                "frame-ancestors 'none'; form-action 'self'"
            ),
            "X-Content-Type-Options": "nosniff",
        })

    @application.get("/assets/app.js", include_in_schema=False)
    def dashboard_script():
        return FileResponse(FRONTEND / "app.js", media_type="text/javascript")

    @application.get("/assets/styles.css", include_in_schema=False)
    def dashboard_styles():
        return FileResponse(FRONTEND / "styles.css", media_type="text/css")

    @application.get("/assets/investigation.js", include_in_schema=False)
    def investigation_script():
        return FileResponse(FRONTEND / "investigation.js", media_type="text/javascript")

    @application.get("/assets/investigation.css", include_in_schema=False)
    def investigation_styles():
        return FileResponse(FRONTEND / "investigation.css", media_type="text/css")

    @application.get("/assets/shieldy.jpg", include_in_schema=False)
    def dashboard_mascot():
        return FileResponse(FRONTEND / "shieldy.jpg", media_type="image/jpeg")

    @application.get("/assets/shieldy-transparent.png", include_in_schema=False)
    def transparent_dashboard_mascot():
        return FileResponse(FRONTEND / "shieldy-transparent.png", media_type="image/png")

    return application


app = create_app()
