# 보안 Tool 정의서

아래 입력·출력·오류는 [코드](../app/scamshield/tools.py)와 [외부 API 어댑터](../api_validation/__main__.py)를 기준으로 정리했습니다. 호출 한도와 이용 조건은 공급자가 정합니다.

## 등록된 Tool

| Tool | 목적 및 입력 | 성공·기록 없음과 반환값 |
|---|---|---|
| `google_safe_browsing` | Google Safe Browsing v5의 알려진 위협 목록 확인. `url: str`은 검증된 공개 HTTP(S) URL로 고정 | `MATCH` 또는 `NO_MATCH`. `matches[]`의 `threat_types`, `literal_url_match`, `cache_duration`. 목록 미일치는 실제 안전을 보증하지 않습니다. |
| `virustotal_url` | VirusTotal v3의 기존 URL 리포트 조회. `url: str` 고정. URL-safe Base64 ID를 사용 | `REPORT`, `NO_RECORD`, `INCOMPLETE_REPORT`. `scope`, `last_analysis_stats`, `last_analysis_date`, `engine_categories`, 조건에 따라 `reported_url_matches` 및 `exact_candidate_id`. |
| `virustotal_domain` | VirusTotal v3의 기존 호스트 리포트 조회. `url: str`에서 호스트를 추출 | `REPORT`, `NO_RECORD`, `INCOMPLETE_REPORT`. `scope=domain`, 분석 시각과 분류 집계. 도메인 관측은 입력 URL의 판정 범위와 구분합니다. |
| `urlscan_history` | 기존 공개 관측 검색. `url: str`에서 호스트만 검색에 사용하고 `days: int`는 1~30. 사용자가 기간을 지정하면 고정 | `CANDIDATES` 또는 `NO_CANDIDATES`. `candidates[]`에는 `domain`, `scan_id`, `observed_at`, `scope`가 포함됩니다. 클라이언트 결과에서는 후보 원문 URL을 가립니다. 조회 기간·페이지 및 추가 조회 오류도 반환할 수 있습니다. |

## 공통 입력과 오류

- Tool 레지스트리는 위 네 이름을 등록합니다. 모델은 제공된 이름과 선택 사유 코드만 제안할 수 있습니다. 실행 URL과 기간은 검증된 Planner 상태에서 가져옵니다.
- 반환 계약은 `check`, `ok`, `outcome`, `data`, `error`입니다. 실패의 `error`에는 코드와 가능할 때 HTTP 상태가 들어갑니다.
- 공통 실패에는 `INVALID_INPUT`, `MISSING_KEY`, `REQUEST_REJECTED`, `AUTH_ERROR`, `RATE_LIMIT`, `TIMEOUT`, `NETWORK_ERROR`, `UPSTREAM_ERROR`, `INVALID_RESPONSE`가 있습니다. VirusTotal의 404와 urlscan.io 빈 검색은 미등록·관측 없음으로 처리합니다.
- 보안 API의 연결·읽기 제한은 각각 3초·10초입니다. Google 캐시는 공급자 유효기간을 적용하고 일치 응답은 최대 30분 재사용합니다. urlscan.io는 10건씩 조회하고 정확 URL이 없고 커서가 있는 때 한 페이지 더 읽습니다.
- 기존 Tool을 추가할 때는 공급자 어댑터의 입출력 계약, Tool 등록, Planner 허용 목록 및 이벤트·판정 코드를 함께 검토합니다. 실호출 예시는 [API 검증](api-validation.md)에 있습니다.

## 공급자가 정하는 한도와 주의사항

| 서비스 | 공식 조건 | 출처 |
|---|---|---|
| Google Safe Browsing | 기본 쿼터와 사용량은 Google Cloud 콘솔에서 확인합니다. 비상업 사용 조건과 출처 표기·경고 안내·정보 갱신 조건이 적용됩니다. 조회 URL과 관련 데이터를 공급자가 이용할 수 있습니다. | [약관](https://developers.google.com/safe-browsing/terms) · [쿼터 안내](https://developers.google.com/safe-browsing/v4/usage-limits) |
| VirusTotal | Public API는 분당 4건, 일 500건이며 상용 제품·서비스에 사용할 수 없습니다. 기존 보고서를 읽는 경로도 지표의 민감도를 고려해야 합니다. Base64 URL ID는 원문을 복원할 수 있습니다. | [Public API](https://docs.virustotal.com/reference/public-vs-premium-api) · [URL 보고서](https://docs.virustotal.com/reference/url-info) · [도메인 보고서](https://docs.virustotal.com/reference/domain-info) |
| urlscan.io | 공개 요금표의 Free 플랜은 검색 1,000건/일입니다. 실제 계정 한도·기간 제한은 공급자 설정과 응답을 확인합니다. 구현은 기존 공개 기록 검색만 사용합니다. | [요금표](https://urlscan.io/pricing/) · [Rate Limits](https://docs.urlscan.io/pages/api-rate-limits) · [검색 명세](https://docs.urlscan.io/apis/urlscan-openapi/search) |

문자 원문은 위 보안 API에 전달하지 않습니다. 공개 URL이나 호스트에 토큰·개인 식별자·사내 정보가 들어갈 수 있으므로 사전 제거가 필요합니다. GMS 인증 설정은 [README](../README.md)에 정리했고 실사용 호출 조건은 발급 계정 기준입니다.
