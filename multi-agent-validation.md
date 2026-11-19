# F3021 Planner·Worker 구조 검증

검증일은 2026-11-18입니다. SSAFY 3회차 프로젝트 명세서 21~22쪽 구현 명세와 25쪽 검증 기준을 적용했습니다. [요구사항 PDF](<../../AI코어프로젝트_3회차_요구사항정의서.pdf>)

## 실행 구조와 선택 방법

| 구조 | 실행 흐름 | 실패 시 처리 |
|---|---|---|
| 단일 Agent | 사용자 분석 → Tool 순서 결정 → 같은 Agent가 직접 실행 → 근거 판단 → 재계획·응답 | 근거 부족을 판단한 Agent가 미사용 Tool로 재계획합니다. |
| Planner·Worker | Planner 분석·작업 목록 생성 → Worker 실행·결과 전달 → 로깅 Agent가 계획과 호출·결과를 대조 → Planner가 근거 판단·재계획·응답 | Worker는 허용된 인자만 같은 Tool에서 한 번 조정할 수 있습니다. 실패하거나 검증에 이상이 있으면 Planner가 남은 허용 Tool로 새 작업 목록을 구성합니다. |

FastAPI 기본 모드는 멀티 Agent입니다. 서버 실행 전에 PowerShell에서 `$env:SCAMSHIELD_AGENT_MODE = "single"`을 지정하면 기존 경로를 사용합니다. `SCAMSHIELD_AGENT_MODE=multi`에서 `$env:SCAMSHIELD_WORKER_LLM = "0"`을 지정하면 Worker LLM만 끕니다. 다른 역할의 판단은 같은 설정을 유지합니다. 기존 API 경로, 응답 형식, 세션, SQLite 저장소와 브라우저 분석 화면을 사용합니다.

## 역할과 교환 데이터

| 구조 | 발신 → 수신 | 필드 |
|---|---|---|
| `PlanBatch` / `Task` / `ToolArguments` | Planner → Worker·로깅 Agent | 실행 ID, 계획 차수, 순서가 있는 작업 ID 목록, Tool 이름, 입력 URL·선택적 조회 일수, 고정 인자 이름과 사용자 조건 |
| `WorkResult` / `Attempt` | Worker → 로깅 Agent·Planner | 작업·실행 ID, 실제 Tool, 실제 인자와 시도 순번, 결과, 실패 코드, 재시도 여부, 계획 변경 요청, 선택 단계 오류 코드 |
| `ValidationResult` | 로깅 Agent → Planner | `verified`·`anomaly`·`needs_review`, 검증 코드, 사용할 수 있는 작업 결과, 계획 변경 요청 |

URL은 항상 고정합니다. 사용자가 기간을 지정하면 조회 일수를 고정하며, 정확 URL 범위와 기간 조건을 Worker에 전달합니다. Worker가 조정 가능한 값은 **사용자가 지정하지 않은 urlscan.io 조회 일수**입니다. 조정한 조회 범위는 기존 날짜·URL 근거 판정을 통과해야 합니다.

`planner.task`, `worker.attempt`, `worker.decision`, `audit.checked`가 기존 `tool.requested`, `tool.finished`, `replan.decided`와 함께 SQLite에 저장됩니다. 브라우저 타임라인에 역할과 검증 결과를 표시합니다. 중간 교환 객체는 메모리에 있으며, 로그에는 URL, 원본 메시지, API 응답 원문, 인증정보를 기록하지 않습니다.

## 모델 호출 조건

- **Planner**는 자연어 의도와 조회의 필요성, 대체 Tool 선택 및 허용된 응답 강조에 기존 모델 호출을 사용합니다. 명확한 인사, 입력 검증, 고정 인자, 증거 판단, 미사용 Tool 선별 및 재계획 상한은 규칙으로 처리합니다.
- **Worker**는 정상 조회와 인증·키 오류, 필수 인자 누락, 수정 가능한 인자가 없는 실패를 규칙으로 처리합니다. 조회 일수가 가변이고 결과 없음·미등록·공급자의 인자 거부에 대해 다른 유효한 기간을 제시할 수 있을 때만 `retry_same_tool`, `skip_task`, `request_new_plan` 중 하나를 모델에 요청합니다. 모델은 URL이나 기간 값을 제출할 수 없습니다. 같은 Tool의 재시도는 최대 1회, Planner 재계획은 기본 최대 2회입니다.
- **로깅 Agent**는 원본 이벤트 수집·저장에 모델을 쓰지 않습니다. 순서·계획 외 호출·고정 인자·반복·재시도·재계획 상한을 규칙으로 대조하고, 불일치한 작업 묶음의 근거를 Planner에게 전달하지 않습니다. 구조상 문제가 없으나 공급자가 일부 데이터만 반환한 보고서에서만 다른 출처 조회와 수동 검토 중 어느 조치가 유용한지 모델에 물을 수 있습니다. 모델 검토가 불완전한 보고서를 완료된 근거로 바꾸지는 않습니다.

## 실제 GMS·외부 API 호출

설정된 GMS 모델과 실제 FastAPI·SQLite를 사용했습니다. 각 항목은 단건이며, 비용을 제한하기 위해 비교 실측의 Planner 재계획 상한은 0회로 설정했습니다. Provider·모델 응답의 지연 차이 때문에 단건으로 성능 우열을 판정할 수 없습니다.

| 모드 / 입력 | 응답 시간 | Planner 재계획 | 전체 LLM / Worker LLM 호출 | 실제 Tool과 처리 |
|---|---:|---:|---:|---|
| 단일, Google만 요청 | 3.008초 | 0 | 2 / 해당 없음 | Google `NO_MATCH`, 정상 완료 |
| 멀티, Worker LLM 끔, 동일 요청 | 2.781초 | 0 | 2 / 0 | Google `NO_MATCH`, 로깅 검증 통과 |
| 멀티, Worker LLM 켬, 동일 요청 | 2.651초 | 0 | 2 / 0 | Google `NO_MATCH`, 로깅 검증 통과 |
| 멀티 켬, 무기록 호스트에서 urlscan.io만 요청 | 4.249초 | 0 | 2 / 1 | `NO_CANDIDATES` 후 동일 Tool 7→14일 재시도. 두 번째도 기록 없음. Worker가 계획 변경을 요청했고, 단일 공급자 조건 안에 남은 작업이 없어 종료했습니다. |
| 멀티 켬, VirusTotal URL 보고서 | 3.045초 | 0 | 2 / 0 | VirusTotal `REPORT`, 로깅 검증 통과 |

모두 HTTP 200이며 GMS 오류는 없었습니다. urlscan.io 재시도에서는 조회 일수만 바뀌고 URL·Tool은 유지됐습니다.

## 모의 비교 및 회귀 검증

같은 공개 URL에 첫 urlscan.io 조회가 비어 있는 상황을 재현했습니다. 입력 하나당 외부 Tool 20ms, 모델 15ms를 주입한 단건 비교입니다. 아래 시간은 모의 하네스의 관측값입니다.

| 모드 | Planner 재계획 | 전체 LLM / Worker LLM 호출 | Tool 실행 | 시간 |
|---|---:|---:|---|---:|
| 단일 | 1 | 3 / 해당 없음 | urlscan.io 7일 → VirusTotal | 0.098초 |
| 멀티, Worker LLM 끔 | 1 | 3 / 0 | urlscan.io 7일 → VirusTotal | 0.094초 |
| 멀티, Worker LLM 켬 | 0 | 3 / 1 | urlscan.io 7일 → 14일, 후보 확보 | 0.090초 |

[신규 테스트](../tests/test_multi_agent.py) 10개와 기존 70개, 총 **80개 통과**. 고정 인자, 키 오류, 필수 인자 누락, 재시도 상한, 복구 실패의 Planner 전달, 실제 호출 이벤트에 끼워 넣은 계획 외 Tool의 결과 제외와 후속 재계획, 동일 입력 반복·상한 감지, 불완전 보고서 모델 검토 및 기존 FastAPI·웹 경로를 검증했습니다. 로컬 Chrome에서도 모의 공급자로 Planner·Worker·로깅 검증 이벤트가 기존 타임라인에 나타나는 것을 확인했습니다.

**F3021 판정은 PASS입니다.** 정상·실패 경로의 실제 GMS 선택과 세 외부 공급자 응답을 확인했습니다. 계획 위반·재계획 상한 초과와 로깅 모델 검토는 외부 서비스 장애를 유발하지 않고 모의 테스트로 검증했습니다. 실제 무기록 입력의 재시도는 성공 결과를 새로 확보하지 못했고, 모드별 응답 시간은 단건 표본입니다. F3020·F3022·F3023은 별도 구현 범위입니다.
