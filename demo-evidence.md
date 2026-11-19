# SCAMSHIELD AI 시연 및 검증 증빙

2026-11-18 제출 준비 시점의 증빙입니다. 입력은 공개 URL과 합성 문구를 사용했습니다. 실호출 결과는 공급자 데이터 및 관측 시각에 따라 바뀔 수 있습니다.

| 시나리오와 입력 예시 | 기대 결과 | 확인된 결과와 검증 유형 | 실제 실행 Tool 또는 모의 실행 Tool | 로그·검증 기록 | 화면 |
| --- | --- | --- | --- | --- | --- |
| 1. URL 모드에서 `https://example.com/`을 Google Safe Browsing으로 확인 요청 | 목록 조회 결과와 한계를 표시 | **Chrome·GMS·보안 API 실호출.** `NO_KNOWN_MATCH`, Google `NO_MATCH` | `google_safe_browsing` | [전체 이벤트 22개](evidence/normal-run.json) | [결과 화면](evidence/normal-result.png) |
| 2. 문자 모드에 “즉시 인증번호를 보내고 입금하세요” 입력 | 인증번호 요구와 송금 압박을 설명 | **Chrome 및 실제 앱의 로컬 문자 규칙.** `SUSPICIOUS`, 정황 표시, URL 조회 없음 | 없음 | [문자 분석 검증 기록](analysis-quality-validation.md) | [결과 화면](evidence/text-result.png) |
| 3. 문자 모드에 “즉시 인증번호를 보내고 입금하세요. https://example.com/ Google Safe Browsing only.” 입력 | 문자 정황과 URL 조회 결과를 함께 표시 | **PASS · Chrome, GMS 및 Google 실호출.** `SUSPICIOUS`, 인증정보 요구·금전 요구·긴급 조치 정황 및 Google `NO_MATCH` 확인 | Planner가 Tool 선택, Worker가 `google_safe_browsing` 호출, 로깅 Agent가 실행 검증 | [전체 이벤트 22개](evidence/mixed-run.json) | [문자·URL 결과](evidence/mixed-result.png) |
| 4. URL 모드에서 `https://example.com/` 조회 | 같은 URL에서 공급자별 결과 차이와 탐지 규모 표시 | **PASS · Chrome, 모의 모델 및 공급자.** Google `NO_MATCH`, VirusTotal `REPORT` 탐지 1·harmless 45, 결과 차이 표시 및 `SUSPICIOUS` | Planner 선택을 모의 모델이 반환, Worker가 `google_safe_browsing`과 `virustotal_url`의 모의 응답 사용, 로깅 Agent가 실행 검증 | [전체 이벤트 28개](evidence/provider-comparison-run.json) | [공급자 비교](evidence/provider-comparison.png) |
| 5. URL 모드에서 `https://example.com/` 조회 | Worker가 URL을 유지하며 기본 조회 기간을 한 번 확대 | **PASS · Chrome, 모의 모델 및 공급자.** 7일 `NO_CANDIDATES` → 14일 `CANDIDATES`, 최종 `INSUFFICIENT_EVIDENCE`, 재계획 0회. 아래 별도 실호출 기록 참고 | Planner가 작업 생성, Worker가 모의 모델의 재시도 선택에 따라 `urlscan_history` 2회 실행, 로깅 Agent가 실행 검증 | [전체 이벤트 25개](evidence/worker-retry-run.json), [Worker 실호출 기록](multi-agent-validation.md), [Planner 재계획 전체 이벤트 39개](evidence/replan-run.json) | [Worker 재시도](evidence/worker-retry.png), [별도 Planner 재계획](evidence/replan-result.png) |
| 6. `https://example.com/`을 같은 7일 조건으로 두 번 호출한 합성 실행 로그 | 중복 경고와 근거 이벤트, 별도 원인 진단 저장 | **PASS · 합성 이벤트, 규칙 평가·GMS 진단 실호출.** `warning`, `DUPLICATE_CALL` 1건, 진단 `completed`. 같은 세션의 Swagger에서 HTTP 200 확인 | 합성 Planner·Worker 이벤트, 실제 로깅 Agent가 판정 및 `diagnose_warning` 실행. `urlscan_history`는 합성 이벤트의 Tool 이름 | [합성 이벤트 11개](evidence/logging-anomaly-run.json), [평가 API 응답](evidence/logging-anomaly-evaluation.json) | [Swagger 경고](evidence/logging-anomaly.png), [진단 본문](evidence/logging-anomaly-diagnosis.png) |
| 7. 시나리오 3의 초안에서 “공식 연락처 확인”과 “공식 앱 알림 확인”을 같은 날짜의 09:00~10:00으로 저장 | 둘 다 저장하고 두 번째 응답에 중복 계획 ID 표시 | **PASS · Chrome, FastAPI, 격리 SQLite 실동작.** 두 응답 모두 HTTP 201. 첫 번째 중복 없음, 두 번째 `has_overlap: true` 및 기존 계획 ID 확인 | 계획 저장 기능을 직접 실행. 저장 중 Agent·보안 Tool 추가 호출 0회 | [분석 로그](evidence/mixed-run.json), [계획 저장 응답](evidence/plan-overlap.json) | [예방 계획 중복 안내](evidence/plan-overlap.png) |

별도 Planner 재계획 시연 입력은 `https://scamshield-api-validation-no-record.example.com/`과 “최근 1시간 이내 기록만 확인해 주세요.”입니다. 실제 보안 API 응답을 규칙 기반 Planner가 처리해 재계획 1회, `REPLAN_LIMIT`, `INSUFFICIENT_EVIDENCE`를 확인했습니다. 이전 Worker 실호출에서도 조회 기간을 7일→14일로 확대했으며 두 조회 모두 `NO_CANDIDATES`였습니다. [멀티 Agent 검증](multi-agent-validation.md)

이번에 추가한 캡처 6장은 1440×960 Chrome 화면입니다. `*-run.json`은 이벤트를 순번대로 담고 내부 입력 참조값을 제거한 제출용 사본입니다. 원인 진단은 평가 API를 Swagger에서 열어 촬영했습니다. [API 검증](api-validation.md) · [최종 검증](final-validation.md)
