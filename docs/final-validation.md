# SCAMSHIELD AI 필수 기능 최종 검증

2026-11-18 기준. 첨부된 3회차 프로젝트 명세서의 2.6 요구사항, 3장 구현 명세, 4장 검증 기준을 대조했습니다. 실측에는 Chrome, FastAPI, 임시 SQLite DB, GMS `gpt-5-nano`와 공개 테스트 데이터만 사용했습니다. 이전 단계에서 수행한 실호출은 표에 별도로 표시했습니다. [프로젝트 명세서](<../../AI코어프로젝트_3회차_요구사항정의서.pdf>)

**PASS**는 해당 범위에 실행 근거가 있고 실호출이 필요한 경우 그 결과를 확보했음을 뜻합니다. **PARTIAL**은 구현 또는 검증 범위에 남은 부분이 있음을, **FAIL**은 요구 동작을 충족하지 못했음을 뜻합니다. 테스트 열은 해당 로컬·모의 회귀 파일입니다.

## F3001~F3019

| 번호 | 구현 파일과 내용 | 테스트 코드 | 실제 검증 결과 | 판정 |
|---|---|---|---|---|
| **F3001** | [tools.py](../app/scamshield/tools.py), [llm.py](../app/scamshield/llm.py). 외부 LangChain Tool 4개, 함수 이름·입력·오류 계약 등록. | [LLM](../tests/test_scamshield_llm.py), [Agent](../tests/test_scamshield_agent.py) | 이번 실측에서 등록 이름을 GMS에 전달하고 Google·urlscan.io 실행 확인. | PASS |
| **F3002** | [API 어댑터](../api_validation/__main__.py), [근거 판단](../app/scamshield/assessment.py). 7일 기본 범위, 공개 스캔 ID·호스트·관측 시각, 정확 URL 우선, 한 페이지 추가 조회, 기존 VirusTotal URL 기록으로 보강. | [API](../tests/test_api_validation.py), [Agent](../tests/test_scamshield_agent.py) | 공개 예시 경로에서 2페이지·20건을 조회하고 미조회 페이지가 있음을 확인. 공개 IANA 안내 URL에서 실제 urlscan.io 무기록과 실제 VirusTotal 일치 보고서로 보강 확인. 이전 후보→상세 연계 성공. | PASS |
| **F3003** | [API 어댑터](../api_validation/__main__.py). 후보 URL에서 VirusTotal 조회 ID를 만들고 리포트 속성을 반환. | [API](../tests/test_api_validation.py) | 이전 실호출에서 URL·도메인 `REPORT`, 미등록 `NO_RECORD`, 후보→상세 `CHAIN_VERIFIED` 확인. | PASS |
| **F3004** | [API 어댑터](../api_validation/__main__.py). Google Safe Browsing 위협 유형과 목록 일치 상태를 보조 근거로 조회. | [API](../tests/test_api_validation.py) | 이번 `NO_MATCH`, 이전 Google 공식 테스트 경로의 `MATCH` 실호출 확인. | PASS |
| **F3005** | [request.py](../app/scamshield/request.py), [agent.py](../app/scamshield/agent.py). 의도·대상·기간·정황 추출과 검증. | [Agent](../tests/test_scamshield_agent.py), [LLM](../tests/test_scamshield_llm.py) | 공개 URL, 합성 송금 문자, 최근 1시간 조건, 도구가 필요 없는 일반 질문 분류 확인. | PASS |
| **F3006** | [agent.py](../app/scamshield/agent.py). 최초 계획과 실행 순서 구성. 단일 공급자 지시를 허용 목록에 적용. | [LLM](../tests/test_scamshield_llm.py) | GMS가 Google과 urlscan.io를 요청에 맞게 선택했고, Google 단독 요청과 일반 대화의 호출 범위 확인. 복수 Tool 순서 전환은 모의 검증했습니다. | PASS |
| **F3007** | [agent.py](../app/scamshield/agent.py), [assessment.py](../app/scamshield/assessment.py). 계획에 따른 호출, 결과 통합과 출처 구분. | [Agent](../tests/test_scamshield_agent.py), [API](../tests/test_api_validation.py) | 이번에 GMS 선택과 실제 호출 일치 확인. 이전 후보→상세 연계 실호출 및 Chrome 부분 실패 화면 확인. | PASS |
| **F3008** | [assessment.py](../app/scamshield/assessment.py). 기준 시각에서 최대 허용 기간을 역산하고 관측 시각·범위를 비교. | [Agent](../tests/test_scamshield_agent.py) | 최근 1시간 기록 없음은 근거 부족으로 응답. 이전 실제 세션 후속 요청에서는 최근 1시간 조건 충족 확인. 정확 범위·경계 계산은 모의 검증했습니다. | PASS |
| **F3009** | [agent.py](../app/scamshield/agent.py). 누락 근거 판단, 미사용 Tool 탐색, 결과 재사용과 상한. | [Agent](../tests/test_scamshield_agent.py), [LLM](../tests/test_scamshield_llm.py) | 이번 GMS는 빈 최근 기록에서 추가 조회 중단을 선택. 이전 실제 무기록 사례에서 대체 Tool 조회와 1회 상한 종료 확인. | PASS |
| **F3010** | [agent.py](../app/scamshield/agent.py), [request.py](../app/scamshield/request.py). 세션별 URL·조건 유지. | [Agent](../tests/test_scamshield_agent.py), [FastAPI](../tests/test_scamshield_api.py) | 앞 단계 실호출에서 URL을 유지한 채 최근 1시간 조건 변경 확인. 세션별 분리 및 연속 대화는 브라우저·TestClient 회귀에서도 확인. | PASS |
| **F3011** | [assessment.py](../app/scamshield/assessment.py), [api_models.py](../app/scamshield/api_models.py), [app.js](../frontend/app.js). 예방 행동과 근거별 제외 사유를 코드·문장으로 반환하고 표시. | [Agent](../tests/test_scamshield_agent.py), [FastAPI](../tests/test_scamshield_api.py), 모의 Chrome | 실제 최근 1시간 조회에서 분석 기록 없음, 시각 미확인, 조회 조건 미충족을 확인. 오래된 근거·URL 범위 불일치·API 실패 문구는 통제 응답으로 Chrome 화면까지 확인. | PASS |
| **F3012** | [events.py](../app/scamshield/events.py), [agent.py](../app/scamshield/agent.py). 순번·시간·Tool·LLM 판단·오류 이벤트 발행. | [로그](../tests/test_execution_logs.py) | 이번 브라우저의 다섯 요청에서 서버의 실제 이벤트 타임라인 확인. 이전 GMS 실행에서 모델이 제공한 사유 코드 저장 확인. | PASS |
| **F3013** | [execution_logs.py](../app/scamshield/execution_logs.py). LLM을 쓰지 않는 구독자와 SQLite 저장. | [로그](../tests/test_execution_logs.py) | 실제 GMS 실행 이벤트를 SQLite에서 조회. 구독자 부재·저장 장애 격리는 로컬 주입 테스트로 확인. | PASS |
| **F3014** | [execution_logs.py](../app/scamshield/execution_logs.py), [FastAPI](../app/scamshield_api.py). 세션별 목록·상세·삭제와 수정 차단. | [로그](../tests/test_execution_logs.py), [FastAPI](../tests/test_scamshield_api.py) | 실제 브라우저 세션에서 조회 200, 삭제 204, 수정 요청 405 및 기타 세션 404 확인. | PASS |
| **F3015** | [prevention_plans.py](../app/scamshield/prevention_plans.py), [plan_models.py](../app/scamshield/plan_models.py). 계획 저장·조회, 일정과 중복 판단. | [계획](../tests/test_prevention_plans.py), [FastAPI](../tests/test_scamshield_api.py) | 실제 GMS 분석 초안으로 두 계획을 201로 저장하고 중복 ID와 상세 200 확인. | PASS |
| **F3016** | [prevention_plans.py](../app/scamshield/prevention_plans.py), [FastAPI](../app/scamshield_api.py). 저장된 계획과 일정 수정·삭제. | [계획](../tests/test_prevention_plans.py), [FastAPI](../tests/test_scamshield_api.py) | 실제 SQLite 계획 수정 200, 중복 해소, 삭제 204 및 세션 분리 확인. | PASS |
| **F3017** | [scamshield_api.py](../app/scamshield_api.py), [api_models.py](../app/scamshield/api_models.py), [api_sessions.py](../app/scamshield/api_sessions.py). 분석·계획·로그 및 소유권 연결. | [FastAPI](../tests/test_scamshield_api.py) | 실제 Chrome과 로컬 서버에서 해당 API 실행. Swagger·OpenAPI는 실제 FastAPI 앱에 대한 TestClient 확인. | PASS |
| **F3018** | [index.html](../frontend/index.html), [styles.css](../frontend/styles.css), [app.js](../frontend/app.js). 분석·계획·로그 화면. | [FastAPI](../tests/test_scamshield_api.py), 이전 Chrome 조작 검증 | 이번 Chrome에서 실제 URL·문자 분석과 근거 렌더링 확인. 이전 Chrome에서 모의 보안 응답으로 저장·편집·삭제 UI와 모바일 뷰포트 확인. | PASS |
| **F3019** | [app.js](../frontend/app.js). 진행 중 상태, 순번·Tool 코드·시간·재계획 및 출처 표시. | [로그](../tests/test_execution_logs.py), 이전 Chrome 조작 검증 | 이번 실제 브라우저에 GMS 선택, Tool 소요 시간과 재계획 검토 후 추가 조회 중단 표시. 실제 대체 호출 이벤트는 이전 API 단계에서, 해당 UI 분기는 모의 Chrome으로 검증. | PASS |

## NF3001~NF3007

| 번호 | 검증 결과 | 판정 |
|---|---|---|
| NF3001 · API 키 관리 | 프로젝트에 빈 Git 저장소를 초기화했습니다. 실제 저장소에서 `.env`, `.env.local`, SQLite 본체·보조 파일 제외를 확인했습니다. 스테이징 후보 42개 파일에 설정된 키·토큰 4개나 검사한 비밀 패턴과 일치한 항목은 0건입니다. 추적 파일·커밋·원격은 0개입니다. 검사할 커밋 이력이 없어 이력 검증은 해당 데이터가 생긴 뒤 가능합니다. | PASS |
| NF3002 · 화면 노출 제한 | API 오류는 고정 메시지·코드로 반환하고 로그는 허용 필드만 저장합니다. 다른 Chrome 세션의 계획·로그 접근은 404였습니다. HTTPS 쿠키 플래그는 TestClient에서 확인했고 실제 Chrome 검증은 로컬 HTTP였습니다. 입력의 개인정보 탐지는 제한적이며 모든 민감 문구를 식별하지 못합니다. | PASS |
| NF3003 · Tool 실패 처리 | 이전 실제 네트워크 실패에서 HTTP 200 부분 응답 및 확보된 근거 제공 확인. 특정 공급자 하나만 실패하는 상황은 모의 TestClient로 검증했습니다. | PASS |
| NF3004 · 재계획 상한 | 기본 2회. 이전 공개 무기록 실호출에서 검증용 상한 1회 종료 확인. 모의 테스트에서 중복 호출 방지와 상한 검사. | PASS |
| NF3005 · 응답 시간 | 이전 대표 실제 요청 3건은 평균 2.89초·최대 3.26초였습니다. 설정 비교에서는 정상 공개 URL 2.39→2.84초, 타임아웃 재현에서 계획 12.06→6.06초, 최종 응답 강조 12.07→3.08초를 확인했습니다. PASS 범위는 로컬 단건 처리와 전환이며, 동시 사용자 부하·장기 지연 분포는 미검증입니다. | PASS |
| NF3006 · 모듈 분리 | 프론트엔드, FastAPI, Agent, 외부 Tool, 이벤트와 저장소가 별도 파일에 있고 실제 HTTP로 연결됩니다. | PASS |
| NF3007 · API 출처·이용 조건 | [API 검증](api-validation.md)에 공식 출처, 무료 한도·약관·공개 조회 범위를 기록했습니다. 공개 예시 데이터로만 재검증했고 신규 스캔을 제출하지 않았습니다. 이 검증은 교육 프로젝트 조건입니다. | PASS |

검증 범위는 개발 환경입니다. 화면은 자체 출처에서만 API를 호출하고 서버가 쿠키 소유권과 요청 출처를 확인합니다. 브라우저에 API 키를 전달하지 않으며 사용자 입력을 텍스트로 렌더링합니다. 배포 환경의 HTTPS 검증과 향후 실제 커밋의 비밀 노출 점검은 남아 있습니다.

## F3002 상세 비교

PDF 10쪽 요구사항 표는 한 API에서 확보하지 못하는 후보를 다른 Tool로 보강하도록 설명합니다. 14~15쪽 구현 명세에는 기본 조회 기준, 다음 Tool이 쓸 식별자·이름, 요청과 실제 조회 기준이 다른 경우의 표시가 포함되며, 별도 출처 보강은 가능한 방식으로 제시됩니다.

- 첫 페이지에서 정확 URL을 찾지 못했고 후속 페이지 커서가 있을 때만 urlscan.io에서 최대 한 페이지 더 읽습니다. 요청 기간·공급자 한도·남은 페이지를 구분하고, 시간 제약은 관측 시각으로 다시 판정합니다. 두 번째 요청 실패 시 첫 페이지 후보와 실패 코드를 함께 유지합니다.
- 정확 URL 스캔이 없으면 이미 조회한 VirusTotal URL 보고서 중 공급자가 돌려준 URL이 입력 URL과 일치하고 보고서 식별자가 있는 항목을 보강 후보로 표시합니다. 이 보강을 위해 같은 Tool을 다시 호출하지 않습니다. URL·기간 조건의 제외 사유는 그대로 적용합니다.
- 두 공급자가 모두 빈 결과를 반환하면 그 범위에서 기록을 찾지 못했다는 사실을 표시합니다. 공개 스캔의 전수 수집이나 미등록 URL 탐지는 보장하지 않습니다. URLhaus는 직접 악성코드를 유포하는 URL을 수집하며 피싱 사이트는 수집 대상에서 제외합니다. 일반 피싱·사칭을 포함하는 이번 검증에서는 기존 VirusTotal을 보강 출처로 사용했습니다. [urlscan.io 페이지 조회 명세](https://docs.urlscan.io/apis/urlscan-openapi/search) · [URLhaus 수집 정책](https://urlhaus.abuse.ch/api/#policy)

## NF3005 단건 측정

로컬 FastAPI의 `POST /api/chat` 왕복을 단건 순차 측정했습니다. 외부 응답 시간과 규칙 전환을 관찰했으며, 마지막 두 행에는 의도적으로 만든 장애가 포함됩니다.

| 입력·상황 | 측정 방식 | 전체 시간 | 주요 구간과 결과 |
|---|---|---:|---|
| 일반 URL | 실제 GMS·Google | 3.26초 | GMS 초기 계획 1.47초 / 응답 1.40초, Google 0.30초 |
| 문자와 URL | 실제 GMS, 유효한 Google 캐시 | 3.13초 | GMS 초기 계획 1.51초 / 응답 1.55초 |
| 실제 재계획 | 규칙 계획, 실제 Google·VirusTotal·urlscan.io | 2.27초 | 0.31초 / 0.76초 / 1.09초. 재계획 1회, `INSUFFICIENT_EVIDENCE` |
| 보안 API 일부 실패 | Google 실호출, VirusTotal에 1초 지연 후 타임아웃 주입 | 1.37초 | `partial`, Google 0.30초 응답 유지 |
| LLM 시간 초과 후 전환 | GMS 12초 읽기 제한을 모의 재현, Google 캐시 | 12.06초 | `LLM_TIMEOUT`, 규칙 경로로 전환, `partial` |

실제 공급자 경로 3건의 평균은 2.89초, 최댓값은 3.26초입니다. 장애 주입 포함 5건은 평균 4.42초, 최댓값 12.06초입니다. 정상 입력은 GMS의 계획·응답 호출이, 장애 상황은 타임아웃 대기가 가장 느린 구간이었습니다. 적용 가능한 근거가 없으면 예방 행동 강조를 위한 마지막 LLM 호출을 생략하고, Google 캐시·기존 Tool 결과 재사용을 유지했습니다.

### LLM 타임아웃 변경 전후

동일한 FastAPI 경로에서 공개 URL의 Google 단독 조회를 각 설정에서 한 번 실제 실행했습니다. 타임아웃 두 시나리오는 실제 GMS 장애를 유발하는 대신, 설정된 읽기 시간만큼 기다린 뒤 `ReadTimeout`을 주입했습니다. 각 설정의 정상 실행으로 채운 Google 캐시를 재사용했습니다.

| 상황 | 기존 12초 설정 | 변경 후 | 응답 검증 |
|---|---:|---:|---|
| GMS와 Google 정상 실호출 | 2.39초 | 2.84초 | 양쪽 모두 HTTP 200, `completed`, Google `NO_MATCH` |
| 초기 계획 읽기 시간 초과 재현 | 12.06초 | 6.06초 | 양쪽 모두 HTTP 200, `partial`, 규칙 기반 Google 조회 |
| 최종 응답 강조 읽기 시간 초과 재현 | 12.07초 | 3.08초 | 양쪽 모두 HTTP 200, `partial`, 확인된 근거와 행동 2개 유지 |

LLM 연결 타임아웃 3초는 유지하며 초기 계획·재계획 읽기 타임아웃을 6초, 검증 결과가 이미 확정된 최종 응답 강조 호출을 3초로 적용합니다. LLM 실패 후 재호출하지 않습니다. 보안 공급자에는 기존 연결 3초·읽기 10초를 유지하고, Google 응답은 공급자 TTL에 따라 재사용합니다. 재계획 상한과 실행별 Tool 결과의 중복 호출 방지는 유지했습니다. 재계획이 실제로 수행되면 추가 LLM과 미사용 Tool 호출 시간이 합산될 수 있습니다. 두 요청만으로 정상 실호출 속도의 변화나 짧은 제한으로 인한 시간 초과 비율을 판단할 수 없으며, 연결 시간과 보안 공급자 호출이 별도로 더해지므로 위 값은 전체 요청의 보장 상한이 아닙니다.

## 회귀 실행

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pip check
node --check frontend/app.js
```

기존 68개와 이번 신규 2개를 합쳐 70개가 통과했습니다. 앞 단계의 요청별 실측은 [API 검증](api-validation.md), GMS 응답 구조와 수정 내용은 [LLM 안정성](llm-stability.md)에 기록했습니다.
