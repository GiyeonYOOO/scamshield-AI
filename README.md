# SCAMSHIELD AI

**의심스러운 문자와 링크의 위험 정황을 살펴보고, 출처별 근거를 예방 행동으로 연결하는 AI 보안 분석 서비스입니다.**

## 2. 프로젝트 개요

SSAFY AI 코어 프로젝트 3회차의 디지털 사기 예방 프로젝트입니다. Planner·Worker·로깅 Agent가 사용자의 요청을 분석하고, 보안 API 결과와 문자 속 정황을 구분해 설명합니다.

## 3. 개발 배경과 문제 정의

피싱 문자에는 인증번호 요구, 긴급 송금 요청, 기관 사칭이 함께 나타날 수 있습니다. 링크만 확인하면 문자 자체의 정황이 사라지고, 한 공급자의 조회 결과만으로 링크의 진위를 확인하기도 어렵습니다. 서비스는 조회 범위와 확인할 수 있는 근거를 밝히고 사용자가 다음 행동을 고르도록 돕습니다.

## 4. 차별점

- 링크가 없는 문자도 문구에서 확인 가능한 위험 표현을 분석합니다.
- Google 목록 결과, VirusTotal 엔진별 집계, urlscan.io 공개 기록을 출처·시각·범위별로 보여 줍니다.
- Agent가 선택한 작업과 재시도를 타임라인에서 확인하고, 예방 행동을 일정으로 저장할 수 있습니다.

## 5. 주요 기능

| 범위 | 기능 |
|---|---|
| 필수 F3001~F3019 | 문자·URL 분석, 외부 Tool, 조건 판단·재계획·메모리, 실행 로그, 예방 계획 CRUD, FastAPI·웹 화면 |
| 심화 F3020 | 규칙 기반 이상 징후 평가, 경고가 있는 실행의 별도 LLM 진단 |
| 심화 F3021 | Planner·Worker 분리, 고정 인자·재시도 상한 검증, 단일 Agent와 비교 |

## 6. 사용자 흐름

1. 웹에서 **URL** 또는 **문자·메신저**를 선택하고 공개 링크나 합성 문구를 입력합니다.
2. 예방 행동, 판단 한계, 공급자별 탐지와 관측 시각을 위에서 아래로 확인합니다.
3. **Agent 실행 과정**에서 분석·조회·재계획 이벤트를 봅니다.
4. 필요한 경우 **예방 계획에 저장**을 눌러 제목과 날짜·시각을 지정합니다. 일정이 겹치면 저장되고 겹친 계획 ID가 표시됩니다.
5. 같은 브라우저 세션에서 계획과 로그를 다시 조회하거나 삭제할 수 있습니다. F3020에서는 실행별 평가 API로 이상 판정과 진단을 조회합니다.

## 7. Planner·Worker·로깅 Agent

Planner가 검증 순서와 고정 조건을 정하고 Worker가 기존 보안 Tool을 실행합니다. 로깅 Agent는 실행 기록을 저장하고 작업과 결과를 대조합니다. Planner는 규칙 검증 결과를 근거로 재계획할 수 있습니다. F3020 진단은 실행 종료 후 별도로 저장합니다. [Agent 설계서](docs/agent-architecture.md)

## 8. 외부 서비스

| 서비스 | 적용 역할 |
|---|---|
| SSAFY GMS / OpenAI 호환 API | Chat Completions Function Calling |
| Google Safe Browsing | 알려진 위협 목록 조회 |
| VirusTotal | 기존 URL·도메인 보고서와 엔진별 분류 집계 |
| urlscan.io | 기존 공개 웹사이트 관측 기록 검색 |

공식 출처, 이용 조건과 인증 방식은 [Tool 정의서](docs/tool-specification.md)에, 실제 호출은 [API 검증](docs/api-validation.md)에 정리했습니다.

## 9. 기술 스택

Python 3.11에서 검증했습니다. FastAPI·Uvicorn·Pydantic, LangGraph·LangChain, SQLite, HTML·CSS·JavaScript를 사용합니다. 자동 검증은 unittest와 FastAPI TestClient로 실행합니다.

## 10. 폴더 구조

```text
app/scamshield_api.py  SCAMSHIELD FastAPI 및 정적 페이지 제공
app/scamshield/       Planner·Worker·Tool·근거 판단·로그·계획 저장
api_validation/       공급자 독립 진단 및 연동 확인 CLI
frontend/             SCAMSHIELD 웹 화면
tests/                단위 및 통합 회귀 테스트
docs/                 제출 문서·검증 기록·증빙
.env.example          비어 있는 서버 설정 예시
requirements.txt      Python 의존성
```

루트 `index.html`과 `app.main`은 기존 Movie Planner 연습 파일입니다. SCAMSHIELD는 아래 진입점으로 실행합니다.

## 11. 설치 및 실행

프로젝트 루트의 Windows PowerShell에서 실행합니다. 패키지 설치는 최초 한 번 수행합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if (-not (Test-Path -LiteralPath .env)) { Copy-Item -LiteralPath .env.example -Destination .env }
```

실호출에 사용할 키는 다음 표에 따라 `.env`에 직접 입력합니다. 서버는 아래 명령으로 시작합니다.

```powershell
$env:SCAMSHIELD_SECURE_COOKIES = "0"
.\.venv\Scripts\python.exe -m uvicorn app.scamshield_api:app --host 127.0.0.1 --port 8000
```

`SCAMSHIELD_SECURE_COOKIES=0`은 로컬 HTTP 테스트용입니다. HTTPS 배포에서는 기본값인 보안 쿠키를 사용합니다. 기본 SQLite 파일은 루트의 `scamshield.sqlite3`이며 Git에서 제외됩니다.

## 12. 환경변수 설정

| 루트 `.env` 키 | 값 |
|---|---|
| `GOOGLE_SAFE_BROWSING_API_KEY` | Safe Browsing API를 활성화한 Google Cloud 프로젝트의 키 |
| `VIRUSTOTAL_API_KEY` | VirusTotal 계정의 API 키 |
| `URLSCAN_API_KEY` | urlscan.io 계정에서 발급한 API 키 |
| `OPENAI_API_KEY` | SSAFY GMS 또는 사용할 OpenAI 호환 API 키 |
| `OPENAI_MODEL` | Function Calling을 지원하는 정확한 모델 ID. 검증 모델은 `gpt-5-nano` |
| `OPENAI_BASE_URL` | OpenAI 직접 연결 시 생략 가능. GMS는 제공받은 HTTPS 기본 주소를 사용하며 코드가 `/chat/completions`를 붙임 |

비교 설정은 서버 실행 전 셸 변수로 지정합니다. `SCAMSHIELD_AGENT_MODE=single`은 단일 Agent, `SCAMSHIELD_WORKER_LLM=0`은 멀티 모드에서 Worker LLM만 비활성화합니다.

## 13. 웹사이트와 Swagger

- [웹사이트](http://127.0.0.1:8000/)
- [Swagger UI](http://127.0.0.1:8000/docs)
- [OpenAPI JSON](http://127.0.0.1:8000/openapi.json)

Swagger에서 `POST /api/chat`을 먼저 실행하면 동일 출처로 세션 쿠키가 발급됩니다. 실행 로그에는 응답의 `run_id`, 예방 계획 저장에는 `plan_draft.analysis_id`를 사용합니다. [API 명세서](docs/api-specification.md)

## 14. 테스트 및 검증

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pip check
node --check frontend/app.js
```

자동 테스트 **103개 통과**. 이전 단계에서 외부 보안 API 세 곳과 GMS Function Calling을 실제 확인했습니다. 공개 입력과 통제 입력의 검증은 구분해 기록합니다. [요구사항 정의](docs/requirements.md) · [기능 검증표](docs/final-validation.md) · [시연 증빙](docs/demo-evidence.md) · [제출 점검표](docs/submission-checklist.md)

## 15. 개인정보 보호와 한계

- 개인 전용 링크와 인증정보를 제거한 뒤 분석하세요. 공급자에 전달할 공개 URL을 검증하더라도 모든 민감한 문자열을 자동으로 감지하는 범위에는 한계가 있습니다.
- 문자 모드는 원문으로 평판 API를 호출하지 않습니다. 유효한 링크가 하나 있으면 그 URL만 조회하며, 모델에는 원문 대신 분류된 정황과 조건을 전달합니다.
- 로그는 허용된 이벤트 필드만 기록합니다. 세션과 계획은 동일 브라우저 쿠키를 기준으로 분리하고, 대화 기억과 미저장 초안은 프로세스 안에서 유지합니다.
- 탐지 일치·미일치와 사기 확정은 별개입니다. 새 피싱이나 변형 문자에는 추가 근거가 필요합니다. 103개 테스트는 기능과 회귀 범위를 확인한 결과입니다.


## 16. 무료 Render 배포 (포트폴리오)

프로젝트 루트의 `render.yaml`로 **Render Web Service — Free** 한 개만 배포합니다.
Python 서버가 `/`의 프론트엔드와 `/api/*` API를 함께 제공합니다.
`/healthz`는 공개 헬스 체크이며 민감한 환경변수를 반환하지 않습니다.

- 배포 명령: `uvicorn app.scamshield_api:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips '*'`
- Render Blueprint 생성 시 `sync: false`로 표시된 API 키는 **Render의 서버 환경변수**에서만 설정합니다. 기존 로컬 `.env`는 업로드하지 않습니다.
- 호스팅 환경변수는 로컬 `.env`보다 우선합니다. `OPENAI_BASE_URL`은 GMS 등 호환 엔드포인트를 이용할 경우 설정하며, 직접 OpenAI에 연결하면 비울 수 있습니다.
- `SCAMSHIELD_SECURE_COOKIES=1`로 HTTPS 쿠키를 사용합니다. API와 정적 페이지가 같은 도메인에서 동작합니다.

**무료 플랜의 저장 제약:** Render Free의 컨테이너 파일은 영구 저장되지 않습니다.
15분간 요청이 없어서 서비스가 휴면하거나, 재시작 또는 재배포되면 `/tmp/scamshield.sqlite3`의 예방 계획·실행 로그·세션이 삭제될 수 있습니다.
따라서 현재 무료 배포는 공개 시연용으로 적합하지만 영구 데이터 저장 서비스는 아닙니다.

**보안 주의:** `.env`, SQLite 원본, Git의 숨겨진 이력, `.venv` 폴더를 GitHub에 업로드하지 않습니다.
본인의 실제 API 키가 채팅이나 외부 공유처에 노출되었다면 발급처에서 재발급하세요.
SSAFY GMS 이용 약관이 외부 공개 서비스에서의 호출을 허용하는지 배포 전에 확인해야 합니다.
요청량이 늘어나면 API 제공업체의 무료 할당량을 소진하거나 비용이 생길 수 있습니다.
