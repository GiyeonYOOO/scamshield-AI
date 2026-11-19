# SCAMSHIELD AI 실행 로그

## F3012 이벤트 발행

메인 Agent는 LangGraph 노드 및 Tool 호출 경계에서 이벤트를 동기 발행합니다. 이벤트 버스는 저장소와 독립적입니다. 각 이벤트에는 세션 참조 ID, 실행마다 생성한 `run_id`, 1부터 시작하는 실행 내 순번 `sequence`, UTC 발생 시각 `occurred_at`, `event_type`, 허용된 상태 값인 `data`를 포함합니다.

| 이벤트 | 저장하는 정보 |
|---|---|
| `run.started`, `run.finished` | 실행 경계, 완료·실패 상태, 확인 가능한 재계획 횟수 |
| `node.entered`, `node.finished` | 노드 이름과 완료·실패 상태 |
| `tool.requested`, `tool.finished` | Tool 이름, URL·호스트 범위, 적용 검색 일수, 결과 코드, 성공 여부, 호출 시간(ms) |
| `llm.decision` | 결정 단계, 검증을 통과한 함수 선택, 모델이 직접 제공한 선택 사유 코드(선택 필드) |
| `replan.decided` | 재계획 여부, 판단 사유, 횟수, 선택된 Tool, 결정 출처 |
| `response.generated` | 최종 응답의 분류 상태 |
| `error.handled` | 안전한 오류 코드, 규칙 경로 전환·계속 진행·예외 전파 여부 |

LLM의 `reason_code`는 허용 목록 안에서 모델이 명시적으로 반환했을 때만 저장합니다. 이 필드는 관측 사실이나 규칙 판단의 근거로 사용하지 않습니다. 실제로 모델이 Google Tool에 `exact_url_report`를 붙인 사례가 있었고, 해당 이벤트는 모델 출력으로만 기록했습니다. 사유 값이 없으면 필드를 생략합니다. URL·Tool 인자는 계속 애플리케이션에서 결정합니다.

## F3013 구독 및 SQLite 저장

별도의 `LoggingAgent`가 이벤트를 구독해 `ExecutionLogs`에 저장합니다. 수집과 저장에 LLM 호출은 없습니다. 구독자가 없거나 저장 중 SQLite 오류가 발생해도 메인 Agent와 다른 구독자는 계속 진행합니다.

| 테이블 | 필드와 제약 |
|---|---|
| `execution_events` | `id` 저장 순서, `session_id` 세션 ID 해시, `run_id` 실행 UUID, `sequence` 실행 내 순번, `occurred_at` UTC 시각, `event_type` 유형, `data` JSON. `(run_id, sequence)`는 고유하며 `(session_id, id)`로 조회를 인덱싱합니다. |
| `deleted_active_runs` | 실행 중 삭제된 로그의 `run_id`만 보관합니다. 남은 이벤트의 재저장을 막으며 종료 이벤트가 오면 표시를 제거합니다. |

발행 시 유형별 허용 필드와 값을 적용합니다. 사용자 입력·응답 원문, URL, API 키, 토큰, 개인정보, 공급자의 응답 본문과 예외 메시지는 로그에 넣지 않습니다. 세션 ID는 SHA-256 참조로 변환합니다. 참조는 같은 세션을 연결하기 위한 값이며 접근 제어 수단으로 쓰지 않습니다.

## F3014 Python 조회 및 삭제

```python
from app.scamshield import ScamshieldAgent
from app.scamshield.events import EventBus
from app.scamshield.execution_logs import ExecutionLogs, LoggingAgent

logs = ExecutionLogs("execution-logs.sqlite")
try:
    bus = EventBus()
    bus.subscribe(LoggingAgent(logs).record)
    agent = ScamshieldAgent(event_bus=bus, decider=None)
    agent.invoke("안녕하세요", session_id="demo")
    runs = logs.list_runs("demo")
    events = logs.get_events("demo", run_id=runs[0]["run_id"])
    deleted_count = logs.delete("demo", run_id=runs[0]["run_id"])
finally:
    logs.close()
```

- `list_runs(session_id)`는 해당 세션의 실행 목록, 시작·종료 시각, 이벤트 수를 반환합니다.
- `get_events(session_id)`는 세션 전체를 저장 순서로 반환합니다. `run_id`를 전달하면 해당 실행을 이벤트 순번으로 조회합니다.
- `delete(session_id, run_id=...)`는 한 실행, `delete(session_id)`는 세션에 저장된 모든 실행 이벤트를 삭제하고 삭제 행 수를 반환합니다.
- 수정 서비스는 제공하지 않으며 SQLite 트리거가 `UPDATE`를 거부합니다.

## 검증 결과 및 제한사항

| 구분 | 결과 |
|---|---|
| 실제 SSAFY GMS `gpt-5-nano`와 Google Safe Browsing | `PASS`. LLM Tool 선택과 명시적 사유, Google `NO_MATCH`, Tool 소요 시간, 응답 생성이 SQLite에 기록됐습니다. 한 실행의 이벤트 18개를 목록·상세로 확인하고 18개를 삭제했습니다. |
| 모의·로컬 테스트 | 기존 32개와 신규 10개, 총 42개 `PASS`. 새 테스트는 노드 전환, Tool 요청·결과·시간, LLM 사유 생략, 재계획, 세션 분리, 조회·삭제, 진행 중 삭제, 수정 차단, 구독자 부재, 저장 장애 격리와 민감정보 미저장을 확인합니다. |
| 의존성 | `pip check` 통과. SQLite는 Python 표준 라이브러리를 사용합니다. |

SQLite 저장은 동기 방식이며 실패한 이벤트는 재시도하지 않습니다. 저장 장애 중 일부 이벤트가 누락될 수 있습니다. 실행 중 삭제 후 프로세스가 종료되어 마지막 이벤트가 오지 않으면 삭제 표시가 DB에 남을 수 있습니다. 세션 접근 권한, 로그 보존 정책, FastAPI 및 화면 연결은 후속 단계입니다.
