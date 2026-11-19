# SCAMSHIELD AI 외부 API 검증

검증일은 2026-11-18입니다. 이 단계에서는 공개 테스트 URL의 보안 근거를 검증합니다. 서비스 목적은 사기 피해 전에 위험 신호를 찾아 예방 행동을 제안하는 것입니다. 후속 MVP에서 문자·URL·스크린샷 입력을 각각 처리하고, 확인한 URL·도메인과 콘텐츠 자체의 위험 신호를 공통 분석 입력으로 전달합니다. 이후 이메일·메신저·음성·영상의 입력 처리를 추가할 수 있습니다.

## 요구사항과 조회 경로

| 번호 | 검증 대상 | 판정 기준 |
|---|---|---|
| F3001 | `api_validation`의 공급자별 호출 함수와 공통 결과·오류 형식 | 입력 범위, 성공 결과, 실패 코드 확인. 메인 Agent에서 같은 함수에 연결되는 LangChain Tool을 등록했습니다. |
| F3002 | urlscan.io 기존 스캔 검색 | 동일 호스트의 최대 10개 기록을 최근 7일 기준으로 요청합니다. 후보 URL·스캔 ID·관측 시각을 읽고 정확 URL 일치와 동일 호스트의 다른 URL을 구분합니다. 조회 기간은 1~30일로 설정할 수 있습니다. |
| F3003 | VirusTotal URL·도메인 리포트 | 입력 URL은 후보 검색 없이 바로 조회합니다. `chain`은 F3002 응답의 후보 URL을 상세 조회 ID로 변환해 분석 통계와 분석 시각을 확인합니다. |
| F3004 | Google Safe Browsing v5 | 사용자 입력 URL을 바로 조회하고, 알려진 위협 유형·문자열 일치 여부·캐시 유효 기간을 확인합니다. |

F3001 검증 명령은 `--help`에 이름과 설명을 등록합니다. 모든 명령은 공개 테스트용 HTTP(S) URL을 입력받고, 검색과 연결 검증의 기간은 `--days`로 지정합니다. 공통 JSON 출력은 `check`, `ok`, `outcome`, `data`, `error`를 포함합니다. 실패 시 `error.code`와 `error.http_status`를 반환합니다. HTTP 요청 전의 실패는 상태 코드가 `null`입니다. HTTP 200의 빈 검색은 정상 응답으로 기록하고, 연결 검증에 필요한 후보가 없는 경우에는 `NO_CHAIN_CANDIDATE`를 반환합니다.

후속 서비스에서는 사용자 입력 URL의 Google 및 VirusTotal URL 조회를 우선 처리하고, urlscan.io 검색과 VirusTotal 도메인 조회를 별도 근거로 결합합니다. 과제의 후보→상세 경로는 `chain`으로 별도 확인합니다. `chain`은 정확히 일치한 URL을 우선 선택하고, 없으면 동일 호스트의 루트 URL을 사용합니다. 루트가 아닌 다른 과거 경로에 개인정보나 토큰이 포함될 수 있으므로 후보 검토 상태를 반환합니다. 동일 호스트의 다른 URL에서 얻은 상세 리포트는 그 후보에 대한 기록입니다.

F3002→F3003 연결은 문서상 가능하며 두 공급자에 같은 URL 기록이 있어야 성립합니다. 실호출에서 URL 리포트 누락이 반복되면 urlscan.io 검색의 스캔 ID를 같은 공급자의 결과 조회에 넘기는 F3003 대안을 검증하고, VirusTotal과 Google을 별도 근거로 활용할 수 있습니다. F3004에서 위협 분류 외의 보조 정보가 필요하면 RDAP로 등록기관·등록일·등록 상태를 조회하는 안을 검토합니다. 등록정보는 사기 판정과 분리합니다. [urlscan.io API](https://docs.urlscan.io/pages/api-intro) · [ICANN RDAP](https://www.icann.org/en/contracted-parties/registry-operators/resources/registration-data-access-protocol)

## 키 발급 및 로컬 설정

- `GOOGLE_SAFE_BROWSING_API_KEY` — Google Cloud 프로젝트를 생성하고 Safe Browsing API를 활성화합니다. 사용자 인증 정보에서 API 키를 만들고 Safe Browsing API로 제한합니다. 기본 쿼터는 콘솔에서 확인합니다. 비상업용 제한과 경고 표시 조건이 있습니다. [키 설정](https://developers.google.com/safe-browsing/v4/get-started) · [이용약관](https://developers.google.com/safe-browsing/terms)
- `VIRUSTOTAL_API_KEY` — VirusTotal Community에 가입하고 개인 설정에서 키를 확인합니다. Public API 한도는 분당 4건, 일 500건이며 비상업용입니다. [키 발급](https://docs.virustotal.com/reference/getting-started) · [사용 제한](https://docs.virustotal.com/reference/public-vs-premium-api)
- `URLSCAN_API_KEY` — urlscan.io 계정에 로그인하고 사용자 설정의 API 키 메뉴에서 키를 생성합니다. 실제 검색 한도는 계정 설정을 기준으로 확인합니다. [API 안내](https://docs.urlscan.io/pages/api-intro) · [한도](https://docs.urlscan.io/pages/api-rate-limits)

프로젝트 루트의 PowerShell에서 실행합니다. 기존 `.env`가 있다면 값을 해당 파일에 추가합니다.

```powershell
if (-not (Test-Path -LiteralPath .env)) { Copy-Item -LiteralPath .env.example -Destination .env }
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

복사한 `.env`의 빈 값에 키를 직접 입력합니다. CLI는 프로젝트 루트의 `.env`를 읽으며 이미 설정된 환경변수를 우선합니다. `.gitignore`가 실제 환경 파일을 제외합니다.

## 실호출 순서

```powershell
.\.venv\Scripts\python.exe -m api_validation google https://example.com/
.\.venv\Scripts\python.exe -m api_validation vt-url https://example.com/
.\.venv\Scripts\python.exe -m api_validation vt-domain https://example.com/
.\.venv\Scripts\python.exe -m api_validation urlscan https://example.com/
.\.venv\Scripts\python.exe -m api_validation chain https://example.com/ --days 30
```

- **Google**은 `NO_MATCH`와 `MATCH`를 구분합니다. 양성 검증에는 `https://testsafebrowsing.appspot.com/s/phishing.html` 또는 `https://testsafebrowsing.appspot.com/s/malware.html`을 브라우저 방문 없이 CLI 입력값으로만 사용합니다. 테스트 호스트의 루트에서는 `NO_MATCH`가 반환되었습니다. [공식 조회 예시](https://developers.google.com/safe-browsing/reference)
- **VirusTotal**은 `REPORT`, `INCOMPLETE_REPORT`, `NO_RECORD`를 구분합니다. 도메인 GET 문서는 조회한 지표도 스캔 및 데이터셋 공개 대상이 될 수 있다고 명시합니다. 두 조회 모두 공개 테스트 대상에만 사용합니다. [URL 리포트](https://docs.virustotal.com/reference/url-info) · [도메인 리포트](https://docs.virustotal.com/reference/domain-info)
- **urlscan.io**는 `CANDIDATES`와 `NO_CANDIDATES`를 구분합니다. 0건이면 조회 기간을 넓히거나 기록이 있는 공개 테스트 URL로 교체합니다. 신규 스캔 제출은 호출하지 않습니다. [검색 명세](https://docs.urlscan.io/pages/search-api-reference)
- **연결 검증**은 기존 리포트의 통계, 분석 시각, 엔진별 분류가 확보된 경우에만 `CHAIN_VERIFIED`를 출력합니다. 후보가 없거나, 검토가 필요한 경로이거나, 상세 데이터가 부족한 경우 각각의 결과를 출력합니다.

CLI는 대상 사이트를 방문하거나 API 리디렉션을 따라가지 않습니다. 결과에는 키, 공급자의 원본 오류 본문, 후보 URL 원문을 출력하지 않습니다. 쿼리·프래그먼트·사용자 정보가 든 URL은 거부하지만 경로에 포함된 민감정보를 완전히 식별할 수 없으므로 공개 테스트 URL만 입력합니다. `NO_MATCH`, `NO_RECORD`, `NO_CANDIDATES`는 각각 다른 조회 결과이며 안전성을 보증하지 않습니다.

## 실행 결과

### 실호출 상태

`PASS`는 인증된 HTTP 응답에서 해당 항목을 확인한 경우, `FAIL`은 실제 호출 결과가 기대와 다른 경우, `NOT_TESTED`는 요청을 전송하지 못한 경우입니다.

| 항목 | 실호출 판정 | 인증·반환 데이터 |
|---|---|---|
| Google Safe Browsing (F3004) | `PASS` | 인증 성공. 공개 예시 URL과 테스트 호스트 루트는 `NO_MATCH`. 공식 피싱·악성코드 테스트 경로는 `MATCH`이며 위협 유형 필드 확인. 보조 근거로 활용 가능. |
| VirusTotal URL 및 도메인 (F3003) | `PASS` | 인증 성공. 두 조회 모두 `REPORT`. 분석 집계, 시각, 엔진별 분류 확인. |
| urlscan.io 공개 검색 (F3002) | `PASS` | 인증 성공. `example.com` 공개 스캔 검색은 `CANDIDATES`. 무기록 테스트용 `example.com` 하위 호스트는 `NO_CANDIDATES`. |
| `chain` (F3002 → F3003) | `PASS` | `CHAIN_VERIFIED`. 30일 범위의 공개 스캔 후보 URL을 VirusTotal에 전달했고 상세 조회는 `REPORT`. |
| VirusTotal 리포트 미등록 실응답 | `PASS` | 2단계 Agent의 무기록 테스트 호스트에서 `NO_RECORD`를 확인했습니다. |

초기 실행은 키가 `.env.example`에 있어 `MISSING_KEY`로 종료됐습니다. 설정을 `.env`로 옮긴 뒤 기본 샌드박스에서는 `NETWORK_ERROR`가 발생했고, 네트워크 접근 승인을 받아 인증 요청을 실행했습니다. Google은 HTTP 200의 `application/x-protobuf` 응답을 기존 JSON 전용 코드가 해석하지 못해 처음에 `INVALID_RESPONSE`로 실패했습니다. Protobuf 파싱을 추가한 후 위협 목록 일치·미일치를 재검증해 모두 통과했습니다. `.env.example`은 빈 템플릿으로 복원했고 `.gitignore`에는 `.env` 제외 규칙이 있습니다.

### 로컬·모의 검증

모의 HTTP 응답 테스트 **14개 PASS**, 실패 0개. 모의 테스트는 공급자별 정상 응답, 빈 결과, 키 누락, 인증·요청 오류, 한도 초과, 서버 오류, 타임아웃, 잘못된 JSON, 분석 필드 누락, 비공개 후보 제외, 후보→상세 전달과 Google Protobuf의 일치·미일치·손상 응답을 검증합니다.

F3002~F3004는 위에 명시한 공개 입력 범위에서 실호출을 확인했습니다. 인증 오류·한도 초과·타임아웃·응답 필드 누락은 모의 검증 결과입니다.

### 2단계 메인 Agent 연동

`ScamshieldAgent.invoke(text, session_id=...)`로 실행합니다. 같은 인스턴스와 세션 ID를 재사용하면 같은 링크에 대한 기간·범위 조건을 이어서 변경할 수 있습니다. 세션에는 URL·조건·문자 정황의 분류만 프로세스 메모리에 보관합니다. 분석과 계획은 규칙 기반이며 이 단계는 한국어 요청과 입력 URL, 문자 정황의 텍스트에 대응합니다.

```powershell
.\.venv\Scripts\python.exe -c "from app.scamshield import ScamshieldAgent; print(ScamshieldAgent().invoke('https://example.com/', session_id='demo'))"
```

F3001은 기존 API 함수에 연결되는 LangChain Tool 4개를 등록합니다. Google 응답은 공급자 유효 기간 범위에서 재사용하며 일치 응답의 보관은 최대 30분입니다. F3005~F3011은 요청 분석, 계획, 실행, 범위·기간 판단, 최대 2회 재계획, 세션 기억 및 근거와 예방 행동 응답을 제공합니다. 외부 조회에는 입력 URL과 필요한 검색 범위만 전달하므로 공개 테스트용 URL을 사용합니다.

| Agent 실행 입력 | 실호출·실행 결과 |
|---|---|
| 공개 예시 URL | Google `NO_MATCH`, VirusTotal URL `REPORT`, 최종 `NO_KNOWN_MATCH` |
| 같은 세션에서 최근 1시간 조건 적용 | URL 유지, 조건 충족, 최종 `NO_KNOWN_MATCH` |
| Google 공식 피싱 테스트 경로 | Google `MATCH`, 최종 `KNOWN_RISK` |
| 공개 예시 도메인의 무기록 테스트 호스트 | VirusTotal `NO_RECORD` 후 urlscan.io `NO_CANDIDATES`, 재계획 1회 상한을 적용한 실행에서 `REPLAN_LIMIT` |

Agent 시나리오 12개와 기존 API 검증 14개는 모의 응답으로 확인했습니다.

### LLM 판단 경로 (F3005~F3011)

`app/scamshield/llm.py`는 프로젝트 루트의 `.env`에서 아래 값을 읽습니다. 기존 보안 API 설정과 함께 두고, `.env.example`에는 빈 예시만 유지합니다.

| 변수 | 설정값 |
|---|---|
| `OPENAI_API_KEY` | 사용하는 API에서 발급한 키 |
| `OPENAI_MODEL` | 계정에 허용된 정확한 모델 ID. Chat Completions function calling을 지원해야 합니다. |
| `OPENAI_BASE_URL` | OpenAI 직접 연결은 비워 두면 `https://api.openai.com/v1`을 사용합니다. SSAFY GMS 또는 호환 게이트웨이는 제공받은 HTTPS API 기본 주소를 입력합니다. 버전 경로는 공급자 안내대로 유지하고 `/chat/completions`는 코드가 붙입니다. |

아래 PowerShell 검증 명령은 공개 URL에 대해 Google 조회를 요청합니다. 초기 모델 결정에 Google Tool이 포함되고, 모델이 선택한 순서대로 실제 보안 Tool 결과가 돌아와야 통과합니다. 이 명령에서 재계획은 0회로 설정하며 출력 항목은 검증 상태·Tool 이름·결과 코드입니다.

```powershell
@'
import json
from app.scamshield import ScamshieldAgent
from app.scamshield.llm import DecisionError, OpenAICompatibleDecider

try:
    model = OpenAICompatibleDecider.from_env()
except (DecisionError, ValueError):
    print(json.dumps({"status": "FAIL", "code": "INVALID_LLM_ENDPOINT"}))
    raise SystemExit(1)
if model is None:
    print(json.dumps({"status": "NOT_TESTED", "code": "LLM_NOT_CONFIGURED"}))
    raise SystemExit(2)

result = ScamshieldAgent(decider=model, max_replans=0).invoke(
    "Check https://example.com/ using only Google Safe Browsing.",
    session_id="llm-verification",
)
decision = next((item for item in result["decisions"]
                 if item["stage"] == "intent_and_plan" and item["source"] == "llm"), {})
selected = decision.get("choices", [])
outcomes = result.get("tool_outcomes", {})
passed = (
    selected == list(outcomes) == ["google_safe_browsing"]
    and outcomes["google_safe_browsing"] in {"MATCH", "NO_MATCH"}
    and not result.get("llm_error")
)
print(json.dumps({
    "status": "PASS" if passed else "FAIL",
    "selected_tools": selected,
    "tool_outcomes": outcomes,
    "llm_error": result.get("llm_error"),
}))
raise SystemExit(0 if passed else 1)
'@ | .\.venv\Scripts\python.exe -
```

일반 요청은 의도와 최초 계획을 한 호출에서 정합니다. 명확한 인사에는 LLM과 보안 API를 모두 생략합니다. 판단 조건을 충족하지 못하고 대안이 남았을 때만 모델에 미사용 Tool을 제시합니다. 최종 응답에서 모델은 기존 관측 근거와 승인된 예방 행동의 강조 순서를 선택하며, 위험 분류·근거 필드·기간 계산·Tool 입력값·호출 상한은 애플리케이션이 결정합니다. 응답의 `decisions`에는 선택 출처가, `assessment_source`에는 근거 평가 출처가 표시됩니다. 모델 설정이 없거나 호출·선택이 실패하면 규칙 기반 경로로 진행합니다.

모델에는 URL 원문과 API 응답 원문을 보내지 않습니다. 여러 줄이거나 의심 정황이 추출된 입력은 정황 분류만 보내고, 그 외에는 흔한 민감 패턴을 가린 짧은 의도 문구가 전송될 수 있습니다. 이 처리는 모든 개인정보 형식을 식별하는 기능까지 보장하지 않습니다.

| 확인 항목 | 검증 방식 | 결과 |
|---|---|---|
| 의도 분석 → 모델 Tool 선택 → LangGraph Tool 실행 | 실제 SSAFY GMS `gpt-5-nano` 및 보안 API | `PASS`. Chat Completions 응답에서 `google_safe_browsing`만 선택했고 LangGraph 실행 결과는 `NO_MATCH`. LLM 오류 없음. |
| 모델 Tool 선택·순서·일반 대화 조회 생략 | 모의 LLM 응답 | `PASS` |
| LLM 인증 실패 후 규칙 경로, 모델의 대상 URL 변경 시도 거부 | 모의 LLM 응답 | `PASS` |
| 전체 회귀 테스트 | 로컬·모의 실행 | 32개 `PASS` |

기본 샌드박스에서 첫 요청은 `LLM_NETWORK_ERROR`로 종료됐습니다. 네트워크 접근이 허용된 첫 실행에서는 Chat Completions와 function calling이 동작했으나 모델이 Google과 VirusTotal을 모두 선택해 단일 공급자 조건에 실패했습니다. 이후 단일 공급자 지시가 기본 계획에 우선하도록 시스템 프롬프트를 보완하고, 최종 실호출에서 Google 단독 선택과 실행을 확인했습니다. [OpenAI Function calling](https://developers.openai.com/api/docs/guides/function-calling)

### 최종 검증 실측 (2026-11-18)

Chrome에서 FastAPI와 SQLite를 실제로 사용하고 GMS `gpt-5-nano`와 보안 서비스에 요청했습니다. 요청 5개에 총 10회의 GMS 호출이 있었고 모두 HTTP 200 및 `finish_reason=tool_calls`를 반환했습니다. 모델 강제 재시도는 없었습니다. 실측에서는 비용을 제한하려고 재계획 상한 1회를 적용했습니다. 기본 상한은 2회입니다.

| 입력 | 모델 선택 및 제어 결정 | 실제 보안 Tool 결과 | 규칙 전환·실패 원인 | 최종 상태 | 화면 대기 |
|---|---|---|---|---|---|
| 공개 URL만 입력 | Google, 예방 행동 우선순위 | Google `NO_MATCH` (312 ms) | 없음 | `NO_KNOWN_MATCH` | 3.41초 |
| Google만 요청 | Google, 예방 행동 우선순위 | Google `NO_MATCH` (캐시) | 없음 | `NO_KNOWN_MATCH` | 3.09초 |
| 합성 송금 요구 문자와 공개 URL | Google, 예방 행동 우선순위 | Google `NO_MATCH` (캐시) | 없음 | `SUSPICIOUS` | 2.81초 |
| 공개 예시 도메인의 무기록 호스트, 최근 1시간 조건 | urlscan.io, `finish_without_lookup`, 예방 행동 우선순위 | urlscan.io `NO_CANDIDATES` (1,074 ms) | 없음. 모델 판단으로 추가 호출 종료 | `INSUFFICIENT_EVIDENCE` | 5.17초 |
| 서비스 설명 질문 | `general_conversation` | 보안 Tool 호출 없음 | 없음 | `GENERAL` | 1.22초 |

Google의 동일 URL 결과는 공급자 응답 유효기간 내 캐시를 사용했으며, Tool 실행 기록과 외부 네트워크 요청을 구분했습니다. 보안 결과의 위험·시간 평가는 모든 요청에서 규칙으로 처리했습니다. 타임라인과 실행 로그는 다섯 실행 모두에서 확인했습니다.

세 공급자의 개별 실호출과 urlscan.io 후보→VirusTotal 연계는 위의 앞 단계 표에 기록했습니다. 최종 재검증에서는 GMS와 Google·urlscan.io를 실제로 다시 호출했고, VirusTotal의 기존 실측 결과를 유지했습니다. 계획 중복 저장·수정과 로그 삭제는 이 Chrome 세션의 실제 SQLite로 확인했습니다.

기존 `auto` 설정의 응답 누락 재현과 새 오류 분류는 [LLM 안정성](llm-stability.md)에 기록했습니다. 회귀 검증은 기존 60개와 신규 3개를 합쳐 63개가 통과했습니다.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```
