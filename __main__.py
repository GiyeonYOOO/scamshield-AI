"""Read-only API checks for public test URLs."""

import argparse
import base64
from dataclasses import dataclass
from io import BytesIO
from itertools import chain
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from dotenv import load_dotenv
import requests


GOOGLE = "https://safebrowsing.googleapis.com/v5/urls:search"
VT = "https://www.virustotal.com/api/v3"
URLSCAN = "https://urlscan.io/api/v1/search/"
ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
DNS_NAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
SUCCESS_OUTCOMES = {"MATCH", "NO_MATCH", "REPORT", "CANDIDATES", "NO_CANDIDATES", "CHAIN_VERIFIED"}
CHECK_DESCRIPTIONS = {
    "google": "입력 URL의 알려진 위협을 조회합니다.",
    "vt-url": "입력 URL의 VirusTotal 리포트를 조회합니다.",
    "vt-domain": "입력 URL 호스트의 VirusTotal 리포트를 조회합니다.",
    "urlscan": "동일 호스트의 기존 공개 스캔을 검색합니다.",
    "chain": "공개 스캔 후보 URL로 VirusTotal 상세 조회를 검증합니다.",
}


class CheckError(Exception):
    def __init__(self, code, status=None):
        self.code = code
        self.status = status


@dataclass
class CheckResult:
    provider: str
    outcome: str
    data: dict


def host_for(url):
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").encode("idna").decode("ascii").lower()
        port = parts.port
    except (ValueError, UnicodeError):
        raise CheckError("INVALID_INPUT") from None
    if (
        parts.scheme not in {"http", "https"}
        or not DNS_NAME.fullmatch(host)
        or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid", ".onion"))
        or parts.username is not None
        or port not in {None, 80, 443}
        or "?" in url
        or "#" in url
        or "\\" in url
        or any(character.isspace() or ord(character) < 32 for character in url)
    ):
        raise CheckError("INVALID_INPUT")
    return host


def read_varint(stream):
    result = 0
    for shift in range(0, 70, 7):
        byte = next(stream, None)
        if byte is None or (shift == 63 and byte > 1):
            raise ValueError("invalid varint")
        result |= (byte & 127) << shift
        if byte < 128:
            return result
    raise ValueError("invalid varint")


def protobuf_fields(payload):
    stream = BytesIO(payload)
    octets = map(ord, iter(lambda: stream.read(1), b""))
    while stream.tell() < len(payload):
        tag = read_varint(octets)
        field, wire = divmod(tag, 8)
        if not field:
            raise ValueError("invalid field number")
        if wire == 0:
            value = read_varint(octets)
        elif wire in {1, 2, 5}:
            size = {1: 8, 5: 4}.get(wire)
            if size is None:
                size = read_varint(octets)
            if size > len(payload) - stream.tell():
                raise ValueError("truncated field")
            value = stream.read(size)
        else:
            raise ValueError("unsupported wire type")
        yield field, wire, value


def decode_google_response(payload):
    names = {
        0: "THREAT_TYPE_UNSPECIFIED", 1: "MALWARE", 2: "SOCIAL_ENGINEERING",
        3: "UNWANTED_SOFTWARE", 4: "POTENTIALLY_HARMFUL_APPLICATION",
    }
    threats = []
    duration = None
    for field, wire, value in protobuf_fields(payload):
        if (field, wire) == (1, 2):
            url = None
            types = []
            for item, kind, content in protobuf_fields(value):
                if (item, kind) == (1, 2):
                    url = content.decode("utf-8")
                elif (item, kind) == (2, 0):
                    types.append(content)
                elif (item, kind) == (2, 2):
                    stream = iter(content)
                    for first in stream:
                        types.append(read_varint(chain((first,), stream)))
            if url is None or not types:
                raise ValueError("incomplete threat")
            threats.append({"url": url, "threatTypes": [names.get(t, f"UNKNOWN_{t}") for t in types]})
        elif (field, wire) == (2, 2):
            parts = {item: content for item, kind, content in protobuf_fields(value) if kind == 0}
            seconds, nanos = parts.get(1, 0), parts.get(2, 0)
            if nanos >= 1_000_000_000 or seconds > 315_576_000_000:
                raise ValueError("invalid cache duration")
            fraction = f".{nanos:09d}".rstrip("0") if nanos else ""
            duration = f"{seconds}{fraction}s"
    return {"threats": threats, "cacheDuration": duration}


def get_json(endpoint, key_name, *, headers=None, params=None):
    key = os.getenv(key_name, "").strip()
    if not key:
        raise CheckError("MISSING_KEY")
    params = dict(params or {})
    request_headers = {"Accept": "application/json", "User-Agent": "SCAMSHIELD-AI/0.1"}
    if headers:
        request_headers[headers] = key
    else:
        params["key"] = key
    try:
        response = requests.get(
            endpoint, headers=request_headers, params=params,
            timeout=(3, 10), allow_redirects=False,
        )
    except requests.Timeout:
        raise CheckError("TIMEOUT") from None
    except requests.RequestException:
        raise CheckError("NETWORK_ERROR") from None

    status = response.status_code
    errors = {400: "REQUEST_REJECTED", 401: "AUTH_ERROR", 403: "AUTH_ERROR", 429: "RATE_LIMIT"}
    if status != 200:
        if status == 404 and endpoint.startswith(VT + "/"):
            raise CheckError("NO_RECORD", status)
        raise CheckError(errors.get(status, "UPSTREAM_ERROR"), status)
    try:
        if endpoint == GOOGLE and response.headers.get("Content-Type", "").split(";")[0] == "application/x-protobuf":
            payload = decode_google_response(response.content)
        else:
            payload = response.json()
    except ValueError:
        raise CheckError("INVALID_RESPONSE", status) from None
    if not isinstance(payload, dict):
        raise CheckError("INVALID_RESPONSE", status)
    return payload


def google_check(url):
    host_for(url)
    payload = get_json(GOOGLE, "GOOGLE_SAFE_BROWSING_API_KEY", params={"urls": url})
    threats = payload.get("threats", [])
    duration = payload.get("cacheDuration")
    if not isinstance(threats, list) or not isinstance(duration, str):
        raise CheckError("INVALID_RESPONSE", 200)
    matches = []
    for threat in threats:
        if (
            not isinstance(threat, dict)
            or not isinstance(threat.get("url"), str)
            or not isinstance(threat.get("threatTypes"), list)
        ):
            raise CheckError("INVALID_RESPONSE", 200)
        matches.append({
            "threat_types": threat["threatTypes"],
            "literal_url_match": threat["url"] == url,
        })
    return CheckResult("google", "MATCH" if matches else "NO_MATCH", {
        "matches": matches, "cache_duration": duration,
    })


def vt_check(url, *, domain=False):
    host = host_for(url)
    if domain:
        resource = f"domains/{host}"
    else:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resource = f"urls/{url_id}"
    payload = get_json(f"{VT}/{resource}", "VIRUSTOTAL_API_KEY", headers="x-apikey")
    data = payload.get("data")
    attributes = data.get("attributes") if isinstance(data, dict) else None
    if not isinstance(attributes, dict):
        raise CheckError("INVALID_RESPONSE", 200)
    stats = attributes.get("last_analysis_stats")
    date = attributes.get("last_analysis_date")
    engines = attributes.get("last_analysis_results")
    if stats is not None and (
        not isinstance(stats, dict) or
        any(type(count) is not int or count < 0 for count in stats.values())
    ):
        raise CheckError("INVALID_RESPONSE", 200)
    if date is not None and type(date) is not int:
        raise CheckError("INVALID_RESPONSE", 200)
    if engines is not None and (
        not isinstance(engines, dict)
        or any(
            not isinstance(verdict, dict) or not isinstance(verdict.get("category"), str)
            for verdict in engines.values()
        )
    ):
        raise CheckError("INVALID_RESPONSE", 200)
    result = {
        "scope": "domain" if domain else "url", "last_analysis_stats": stats,
        "last_analysis_date": date,
        "engine_categories": (
            {name: verdict["category"] for name, verdict in engines.items()}
            if engines is not None else None
        ),
    }
    reported_url = attributes.get("url")
    report_id = data.get("id")
    if not domain and isinstance(reported_url, str):
        try:
            matches = _url_identity(reported_url) == _url_identity(url)
        except CheckError:
            matches = False
        result["reported_url_matches"] = matches
        if matches and isinstance(report_id, str) and report_id:
            result["exact_candidate_id"] = report_id
    return CheckResult("virustotal", "REPORT" if stats and date and engines else "INCOMPLETE_REPORT", result)


def _scan_entries(payload):
    results = payload.get("results")
    if not isinstance(results, list):
        raise CheckError("INVALID_RESPONSE", 200)
    return results


def _url_identity(url):
    parts = urlsplit(url)
    default_port = 443 if parts.scheme == "https" else 80
    return parts.scheme, host_for(url), parts.port or default_port, parts.path or "/"


def _scan_candidates(results, url):
    identity = _url_identity(url)
    candidates = []
    seen = set()
    for entry in results:
        if not isinstance(entry, dict):
            continue
        task = entry.get("task")
        if not isinstance(task, dict) or task.get("visibility", "public") != "public":
            continue
        candidate = task.get("url")
        scan_id = task.get("uuid") or entry.get("_id")
        if not isinstance(candidate, str) or not isinstance(scan_id, str) or scan_id in seen:
            continue
        try:
            candidate_identity = _url_identity(candidate)
        except CheckError:
            continue
        if candidate_identity[1] != identity[1]:
            continue
        seen.add(scan_id)
        candidates.append({
            "url": candidate, "domain": candidate_identity[1], "scan_id": scan_id,
            "observed_at": task.get("time"),
            "scope": "exact_url" if candidate_identity == identity else "same_host",
        })
    return sorted(candidates, key=lambda item: item["scope"] != "exact_url")


def _scan_page_after(payload, results):
    total = payload.get("total")
    if results and (payload.get("has_more") is True or type(total) is int and total > len(results)):
        last = results[-1]
        cursor = last.get("sort") if isinstance(last, dict) else None
        if isinstance(cursor, list) and cursor and all(type(value) in {str, int} for value in cursor):
            return ",".join(map(str, cursor))
    return None


def urlscan_check(url, days=7):
    host = host_for(url)
    params = {
        "q": f'task.domain.keyword:"{host}" AND task.visibility:public AND date:>now-{days}d',
        "size": 10,
    }
    payload = get_json(URLSCAN, "URLSCAN_API_KEY", headers="API-Key", params=params)
    results = _scan_entries(payload)
    candidates = _scan_candidates(results, url)
    pages_searched, supplement_error = 1, None
    cursor = _scan_page_after(payload, results)
    if cursor and not any(item["scope"] == "exact_url" for item in candidates):
        try:
            more = get_json(URLSCAN, "URLSCAN_API_KEY", headers="API-Key",
                            params={**params, "search_after": cursor})
            results = results + _scan_entries(more)
        except CheckError as error:
            supplement_error = error.code
        else:
            pages_searched += 1
            candidates = _scan_candidates(results, url)
    limit = payload.get("search_date_limit_days")
    total = payload.get("total")
    has_more = payload.get("has_more") is True or (type(total) is int and total > len(results))
    return CheckResult("urlscan", "CANDIDATES" if candidates else "NO_CANDIDATES", {
        "search_host": host, "days": days, "record_count": len(results),
        "candidates": candidates, "pages_searched": pages_searched,
        "additional_results_available": has_more, "supplement_error": supplement_error,
        "effective_days": min(days, limit) if type(limit) is int and limit > 0 else days,
    })


def chain_check(url, days=7):
    search = urlscan_check(url, days)
    candidates = search.data["candidates"]
    if not candidates:
        return CheckResult("chain", "NO_CHAIN_CANDIDATE", search.data)
    # Only the user-supplied test URL or a query-free host root is sent to VT.
    # A historical path needs separate review before it can be forwarded.
    exact_matches = [item for item in candidates if item["scope"] == "exact_url"]
    roots = [item for item in candidates if urlsplit(item["url"]).path in {"", "/"}]
    eligible = exact_matches or roots
    candidate = (eligible or candidates)[0]
    result = {
        "scan_id": candidate["scan_id"], "candidate_scope": candidate["scope"],
        "observed_at": candidate["observed_at"],
    }
    if not eligible:
        return CheckResult("chain", "CANDIDATE_REVIEW_REQUIRED", result)
    try:
        detail = vt_check(candidate["url"])
    except CheckError as error:
        result.update(detail_outcome=error.code, detail_http_status=error.status)
        return CheckResult("chain", "DETAIL_UNAVAILABLE", result)
    result.update(detail_outcome=detail.outcome, detail=detail.data)
    outcome = "CHAIN_VERIFIED" if detail.outcome == "REPORT" else "DETAIL_INCOMPLETE"
    return CheckResult("chain", outcome, result)


def run_check(name, url, days=7):
    checks = {
        "google": lambda: google_check(url),
        "vt-url": lambda: vt_check(url),
        "vt-domain": lambda: vt_check(url, domain=True),
        "urlscan": lambda: urlscan_check(url, days),
        "chain": lambda: chain_check(url, days),
    }
    try:
        result = checks[name]()
    except CheckError as error:
        return {
            "check": name, "ok": False, "outcome": error.code, "data": None,
            "error": {"code": error.code, "http_status": error.status},
        }
    data = result.data
    if "candidates" in data:
        data = {**data, "candidates": [
            {key: value for key, value in candidate.items() if key != "url"}
            for candidate in data["candidates"]
        ]}
    ok = result.outcome in SUCCESS_OUTCOMES
    return {
        "check": name, "ok": ok, "outcome": result.outcome, "data": data,
        "error": None if ok else {
            "code": result.outcome, "http_status": data.get("detail_http_status", 200),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="공개 테스트 URL에 대한 읽기 전용 API 검증")
    subparsers = parser.add_subparsers(dest="check", required=True)
    for name, description in CHECK_DESCRIPTIONS.items():
        command = subparsers.add_parser(name, help=description)
        command.add_argument("url", help="개인정보나 인증 토큰이 없는 공개 테스트 URL")
        # Keep the previously accepted option on each command.
        command.add_argument("--days", type=int, choices=range(1, 31), default=7, metavar="1..30")
    args = parser.parse_args()
    load_dotenv(ENV_PATH)
    result = run_check(args.check, args.url, args.days)
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
