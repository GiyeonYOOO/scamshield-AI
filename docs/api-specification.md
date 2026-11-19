# FastAPI 명세서

실제 라우트는 [서버](../app/scamshield_api.py), 스키마는 [Pydantic 모델](../app/scamshield/api_models.py)을 기준으로 합니다. 실행 후 [Swagger UI](http://127.0.0.1:8000/docs)와 [OpenAPI JSON](http://127.0.0.1:8000/openapi.json)에서 전체 필드를 확인할 수 있습니다. 아래 JSON은 화면 흐름을 보여 주는 예시이며 응답의 핵심 필드를 발췌했습니다.

## 세션과 접근 범위

`POST /api/chat`을 쿠키 없이 처음 성공하면 서버가 `scamshield_session`을 발급합니다. 쿠키는 `HttpOnly`, `SameSite=Strict`, `Path=/api`, 최대 7일이며 기본적으로 `Secure`가 켜집니다. 로컬 HTTP 실행법은 [README](../README.md)를 참고합니다. 이후에는 같은 출처에서 쿠키를 함께 전송해야 합니다.

서버가 정한 세션 소유자로 계획·로그·평가를 분리합니다. 클라이언트는 소유자 ID를 지정할 수 없습니다. 다른 세션의 항목은 404를 반환합니다. 변경 요청에 브라우저의 `Origin`이 있고 요청 출처와 다르면 403을 반환합니다.

## 라우트

| 메서드·경로 | 정상 상태 | 내용 |
|---|---:|---|
| `POST /api/chat` | 200 | 메시지와 입력 모드를 분석합니다. 실행 ID, 처리 상태, 근거, 행동 및 가능한 경우 계획 초안을 반환합니다. |
| `POST /api/plans` | 201 | 동일 세션의 유효한 분석 초안에서 예방 계획을 저장합니다. |
| `GET /api/plans` | 200 | 현재 세션의 계획 목록 |
| `GET /api/plans/{plan_id}` | 200 | 계획 상세 |
| `PATCH /api/plans/{plan_id}` | 200 | 제목, 행동 목록 또는 일정을 부분 수정합니다. 수정 후 중복 여부를 다시 계산합니다. |
| `DELETE /api/plans/{plan_id}` | 204 | 계획 삭제. 응답 본문 없음 |
| `GET /api/logs` | 200 | 현재 세션의 실행 목록과 이벤트 수 |
| `GET /api/logs/{run_id}` | 200 | 순번순 원본 이벤트 |
| `GET /api/logs/{run_id}/evaluation` | 200 | F3020 판정, 근거 이벤트와 별도 진단 |
| `DELETE /api/logs/{run_id}` | 204 | 실행 로그 및 관련 판정·진단 삭제. 응답 본문 없음 |

## 분석 요청 예시

`POST /api/chat`

```json
{"message":"즉시 인증번호를 보내고 입금하세요","target_type":"text"}
```

`message`는 공백 정리 후 1~4000자입니다. 기본 `target_type`은 `url`이며 `text`를 사용할 수 있습니다. 모델의 타입에는 `screenshot`도 있지만 이 경로는 JSON 텍스트를 읽으며, 현재 화면에는 스크린샷 파일 업로드가 없습니다.

```json
{
  "run_id":"0123456789abcdef0123456789abcdef",
  "status":"completed",
  "analysis":{
    "status":"SUSPICIOUS",
    "message":"문자에서 의심 정황을 발견했습니다. 발신자와 요청의 진위는 공식 경로에서 확인하세요.",
    "text_assessment":{"status":"signals_found","url_lookup":"not_attempted"},
    "local_signals":["인증정보 요구 표현","금전 요구 표현","긴급 조치 표현"],
    "tool_outcomes":{},
    "evidence":[]
  },
  "plan_draft":{
    "analysis_id":"0123456789abcdef0123456789abcdef",
    "target_type":"text",
    "actions":["확인 전에는 인증번호·개인정보를 보내거나 송금하지 마세요."]
  }
}
```

최상위 `status`는 처리 상태인 `completed` 또는 `partial`입니다. `analysis.status`는 `GENERAL`, `KNOWN_RISK`, `SUSPICIOUS`, `NO_KNOWN_MATCH`, `INSUFFICIENT_EVIDENCE` 중 하나입니다. 부분 성공에서는 알려진 근거와 `tool_errors` 또는 `llm_error`를 같이 확인합니다. 조회 실행과 공급자의 탐지 여부는 각각 `tool_outcomes` 및 `evidence`에 표시됩니다.

## 예방 계획 예시

`POST /api/plans`

```json
{"analysis_id":"0123456789abcdef0123456789abcdef","title":"공식 연락처 확인","execution_date":"2026-11-18","start_time":"09:00","end_time":"10:00"}
```

성공 응답은 `plan`, `has_overlap`, `overlapping_plan_ids`를 반환합니다. 일정이 겹쳐도 201로 저장합니다. 초안은 현재 프로세스에서 최대 1시간 유지되고 재시작 시 초기화됩니다.

```json
{
  "plan":{
    "id":"abcdef0123456789abcdef0123456789",
    "analysis_id":"0123456789abcdef0123456789abcdef",
    "title":"공식 연락처 확인","target_type":"text",
    "actions":["기관의 공식 앱에서 알림을 확인하세요."],
    "execution_date":"2026-11-18","start_time":"09:00:00","end_time":"10:00:00",
    "created_at":"2026-11-18T00:00:00+00:00","updated_at":"2026-11-18T00:00:00+00:00"
  },
  "has_overlap":true,
  "overlapping_plan_ids":["fedcba9876543210fedcba9876543210"]
}
```

`PATCH /api/plans/{plan_id}` 예시는 다음과 같습니다.

```json
{"title":"공식 연락처 재확인","actions":["기관의 공식 앱에서 알림을 확인하세요."],"start_time":"10:00","end_time":"11:00"}
```

날짜는 `YYYY-MM-DD`, 입력 시각은 `HH:MM` 또는 `HH:MM:SS`입니다. 종료 시각은 같은 날 시작보다 늦어야 합니다. 부분 수정은 명시한 유효 필드만 바꿉니다.

## 실행 로그와 F3020

로그 목록은 실행 ID·시작·종료 시각·이벤트 수의 배열입니다. 상세 응답은 `run_id`, `events[]`를 반환하고 이벤트에는 `sequence`, `occurred_at`, `event_type`, `data`가 들어갑니다. 조회된 원본 예시는 [시연 증빙](demo-evidence.md)에 있습니다.

`GET /api/logs/{run_id}/evaluation`의 정상 판정 예시입니다.

```json
{"run_id":"0123456789abcdef0123456789abcdef","status":"normal","warnings":[],"complete":true,"reason":null,"diagnosis":null}
```

`warnings`의 각 항목에는 `code`, 위치(`revision`, `sequence`), 이유와 근거 이벤트 ID가 있습니다. `inconclusive`는 판단 자료 부족이며, 모델 진단은 `diagnosis` 필드에서 별도로 확인합니다.

## 오류 응답

| HTTP | 대표 오류 코드와 의미 |
|---|---|
| 401 | `SESSION_REQUIRED` 세션 없음·유효하지 않은 세션 |
| 403 | `ORIGIN_REJECTED` 변경 요청의 출처 불일치 |
| 404 | `PLAN_NOT_FOUND`, `LOG_NOT_FOUND`, `DRAFT_NOT_FOUND` 현재 세션에서 조회 불가 |
| 405 | `METHOD_NOT_ALLOWED` 지원하지 않는 메서드 |
| 422 | `INVALID_REQUEST`, `INVALID_URL`, `INVALID_SCHEDULE` 입력 검증 실패 |
| 500 / 503 | `INTERNAL_ERROR` / `STORAGE_UNAVAILABLE` |

```json
{"error":{"code":"SESSION_REQUIRED","message":"유효한 세션이 필요합니다. 먼저 분석 요청으로 세션을 시작하세요."}}
```
