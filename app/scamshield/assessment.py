"""F3008 and F3011: evaluate scoped evidence and give preventive actions."""

from datetime import datetime, timedelta, timezone


DEFAULT_FRESHNESS_HOURS = 168
SOURCE_LABELS = {
    "google_safe_browsing": "Google Safe Browsing",
    "virustotal_url": "VirusTotal URL",
    "virustotal_domain": "VirusTotal 도메인",
    "urlscan_history": "urlscan.io",
}
HEADLINES = {
    "KNOWN_RISK": "조회 대상에 적용되는 알려진 위험 정보가 확인됐습니다.",
    "SUSPICIOUS": "의심 정황이 있으나 사기로 확정할 근거는 부족합니다.",
    "NO_KNOWN_MATCH": "Google의 알려진 위협 목록에서 일치하는 기록을 확인하지 못했습니다. 새 위협이나 미탐지 가능성은 남아 있습니다.",
    "INSUFFICIENT_EVIDENCE": "검사에 필요한 정보가 부족하거나 일부 검증을 완료하지 못했습니다.",
}
USABLE_OUTCOMES = {"MATCH", "NO_MATCH", "REPORT", "CANDIDATES"}
EXCLUSION_LABELS = {
    "NO_RECORD": "요청한 범위의 분석 기록을 찾지 못했습니다.",
    "STALE_EVIDENCE": "관측 기록이 판단에 적용하는 기간보다 오래됐습니다.",
    "URL_SCOPE_MISMATCH": "입력한 URL과 같은 범위의 기록이 아닙니다.",
    "QUERY_CONDITION_UNMET": "요청하신 조회 기간 또는 URL 범위 조건을 충족하지 못했습니다.",
    "API_ERROR": "외부 API 조회 오류로 검증하지 못했습니다.",
    "OBSERVATION_TIME_UNAVAILABLE": "관측 시각을 확인할 수 없습니다.",
    "INVALID_OBSERVATION_TIME": "관측 시각이 조회 시각보다 뒤여서 사용할 수 없습니다.",
    "INCOMPLETE_REPORT": "분석 보고서의 필수 데이터가 부족합니다.",
}


def _exclusion_reasons(item, age, max_age, freshness_hours):
    outcome = item["outcome"]
    if outcome in {"NO_RECORD", "NO_CANDIDATES"}:
        return ["NO_RECORD"]
    if outcome == "INCOMPLETE_REPORT":
        return ["INCOMPLETE_REPORT"]
    if outcome not in USABLE_OUTCOMES:
        return ["API_ERROR"]
    reasons = []
    if not item["scope_met"]:
        reasons.append("URL_SCOPE_MISMATCH")
    if age is None and (max_age is not None or item["tool"] != "google_safe_browsing"):
        reasons.append("OBSERVATION_TIME_UNAVAILABLE")
    elif age is not None:
        if age > freshness_hours:
            reasons.append("STALE_EVIDENCE")
        elif age < 0:
            reasons.append("INVALID_OBSERVATION_TIME")
    if not item["scope_met"] or (max_age is not None and not item["freshness_met"]):
        reasons.append("QUERY_CONDITION_UNMET")
    return reasons


def timestamp(value):
    try:
        if type(value) is int:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    return None


def _provider_comparison(eligible):
    google = [item for item in eligible if item["tool"] == "google_safe_browsing"]
    vt = [item for item in eligible if item["tool"].startswith("virustotal_")
          and item["outcome"] == "REPORT" and item.get("engine_counts")]
    if not google or not vt:
        return None
    google_exact = next((item for item in google if item["scope"] == "exact_url"), None)
    vt_exact = next((item for item in vt if item["scope"] == "exact_url"), None)
    if google_exact is None or vt_exact is None:
        return "scope_differs"
    counts = vt_exact["engine_counts"]
    google_hit = google_exact["outcome"] == "MATCH"
    vt_hit = counts.get("malicious", 0) > 0
    if google_hit and vt_hit:
        return "agreement"
    if google_exact["outcome"] == "NO_MATCH" and vt_hit:
        return "different"
    if google_hit and not vt_hit and not counts.get("suspicious", 0) and counts.get("harmless", 0):
        return "different"
    return None


def assess(request, results, now):
    conditions = request["conditions"]
    max_age = conditions.get("max_age_hours")
    exact_only = conditions.get("exact_only", False)
    freshness_hours = max_age or DEFAULT_FRESHNESS_HOURS
    evidence = []
    scan = results.get("urlscan_history")
    missing_exact_scan = scan is not None and not any(
        item["scope"] == "exact_url" for item in (scan.get("data") or {}).get("candidates", [])
    )
    for name, result in results.items():
        data = result.get("data") or {}
        base = {"tool": name, "source": SOURCE_LABELS[name], "outcome": result["outcome"]}
        if name == "urlscan_history":
            if data.get("days") is not None:
                base.update(requested_search_days=data["days"], searched_days=data.get("effective_days", data["days"]),
                            candidate_pages=data.get("pages_searched", 1),
                            candidate_more_available=data.get("additional_results_available", False))
            if not data.get("candidates"):
                evidence.append({**base, "scope": "host_search", "signal": None})
            for candidate in data.get("candidates", []):
                evidence.append({
                    **base, "scope": candidate["scope"], "signal": None,
                    "scan_id": candidate["scan_id"], "observed_at": candidate["observed_at"],
                })
            if data.get("supplement_error"):
                evidence.append({**base, "outcome": data["supplement_error"], "scope": "host_search",
                                 "signal": None, "supplemental_search": True})
        elif name == "google_safe_browsing":
            for match in data.get("matches", []):
                evidence.append({
                    **base, "scope": "exact_url" if match["literal_url_match"] else "url_expression",
                    "signal": "known_risk", "threat_types": match["threat_types"],
                })
            if not data.get("matches"):
                signal = "no_match" if result["outcome"] == "NO_MATCH" else None
                evidence.append({**base, "scope": "exact_url", "signal": signal})
        else:
            stats = data.get("last_analysis_stats") or {}
            detections = stats.get("malicious", 0)
            signal = (
                "known_risk" if detections >= 2 else
                "suspicious" if detections or stats.get("suspicious", 0) else None
            )
            item = {
                **base, "scope": "exact_url" if name == "virustotal_url" else "same_host",
                "signal": signal, "observed_at": data.get("last_analysis_date"),
                "engine_counts": stats,
                "reported_engines": sum(stats.values()) if stats else None,
                "detection_strength": (
                    "multiple_engines" if detections >= 2 else "single_engine" if detections == 1 else None
                ),
            }
            if name == "virustotal_url" and data.get("reported_url_matches") is False:
                item.update(scope="reported_url_mismatch", signal=None)
            if missing_exact_scan and name == "virustotal_url" and result["outcome"] == "REPORT":
                if data.get("exact_candidate_id"):
                    item["supplemental_candidate_id"] = data["exact_candidate_id"]
            evidence.append(item)

    for item in evidence:
        observed = timestamp(item.get("observed_at"))
        age = (now - observed).total_seconds() / 3600 if observed else None
        item["observed_at"] = observed.isoformat() if observed else None
        item["age_hours"] = round(age, 3) if age is not None else None
        item["scope_met"] = item["scope"] != "reported_url_mismatch" and (
            not exact_only or item["scope"] == "exact_url"
        )
        item["freshness_met"] = age is not None and 0 <= age <= freshness_hours
        reasons = _exclusion_reasons(item, age, max_age, freshness_hours)
        item["eligible"] = not reasons
        item["exclusion_reasons"] = [
            {"code": code, "message": EXCLUSION_LABELS[code]} for code in reasons
        ]

    eligible = [item for item in evidence if item["eligible"]]
    dated = [item for item in eligible if item["freshness_met"] and item["outcome"] in {"CANDIDATES", "REPORT"}]
    covered = any(item["scope"] in {"exact_url", "url_expression"} for item in eligible if (
        item["outcome"] in {"MATCH", "NO_MATCH", "REPORT", "CANDIDATES"}
    ))
    # A host's reputation is context. It cannot establish a threat on a specific URL.
    known = any(
        item["signal"] == "known_risk" and item["scope"] != "same_host" for item in eligible
    )
    suspicious = request["signals"] or any(
        item["signal"] in {"known_risk", "suspicious"} for item in evidence
    )
    no_match = any(item["signal"] == "no_match" for item in evidence)
    constraints_met = bool(dated) if max_age is not None else bool(covered or dated)
    if known:
        status = "KNOWN_RISK"
    elif suspicious:
        status = "SUSPICIOUS"
    elif constraints_met and no_match:
        status = "NO_KNOWN_MATCH"
    else:
        status = "INSUFFICIENT_EVIDENCE"
    return {
        "status": status, "evidence": evidence, "known": known,
        "provider_comparison": _provider_comparison(eligible),
        "constraints_met": constraints_met, "dated_evidence": bool(dated),
        "freshness_hours": freshness_hours,
        "minimum_observed_at": (now - timedelta(hours=freshness_hours)).isoformat(),
    }


def final_response(request, assessment, results, replans, stop_reason):
    if request["kind"] == "chat":
        return {"status": "GENERAL", "message": "안녕하세요. 의심스러운 문자 내용이나 확인할 공개 URL을 알려 주세요."}
    if request["kind"] == "text_only":
        suspicious = bool(request["signals"])
        message = (
            "문자에서 의심 정황을 발견했습니다. 발신자와 요청의 진위는 공식 경로에서 확인하세요."
            if suspicious else "문자에서 정의된 위험 표현을 발견하지 못했습니다. 발신자와 요청의 진위는 확인하지 못했습니다."
        )
        issue = request.get("issue")
        if issue == "MULTIPLE_URLS":
            message += " 링크가 여러 개 있으므로 URL을 검증하려면 하나를 선택하세요."
        elif issue == "INVALID_OR_SENSITIVE_URL":
            message += " 문자는 분석했으며 URL 검증에는 인증 정보가 없는 공개 링크가 필요합니다."
        return {
            "status": "SUSPICIOUS" if suspicious else "INSUFFICIENT_EVIDENCE",
            "message": message, "issue": issue, "local_signals": request["signals"],
            "evidence": [], "actions": [
                "확인 전에는 인증번호·개인정보를 보내거나 송금하지 마세요."
                if suspicious else "금전이나 개인정보 요청이 있다면 기관의 공식 연락처로 확인하세요.",
            ],
        }
    if request["kind"] == "clarify":
        prompts = {
            "URL_REQUIRED": "검사할 공개 URL을 알려 주세요.",
            "MULTIPLE_URLS": "검사할 공개 URL 하나를 골라 주세요.",
            "INVALID_OR_SENSITIVE_URL": "인증 정보가 없는 공개 HTTP(S) URL을 입력해 주세요.",
            "INVALID_PERIOD": "조회 기간은 1시간에서 30일 사이로 입력해 주세요.",
        }
        return {
            "status": "SUSPICIOUS" if request["signals"] else "INSUFFICIENT_EVIDENCE",
            "message": (
                f'{HEADLINES["SUSPICIOUS"]} {prompts[request["issue"]]}'
                if request["signals"] else prompts[request["issue"]]
            ),
            "issue": request["issue"], "local_signals": request["signals"],
            "evidence": [], "actions": ["의심 문자에 답장하거나 인증번호를 전달하기 전에 공식 연락처로 확인하세요."],
        }

    status = assessment["status"]
    message = HEADLINES[status]
    detected = [item for item in assessment["evidence"] if item["eligible"]]
    google_hit = any(item["tool"] == "google_safe_browsing" and item["outcome"] == "MATCH" for item in detected)
    if status == "KNOWN_RISK":
        message = (
            "Google Safe Browsing의 알려진 위협 목록에서 일치 기록을 확인했습니다."
            if google_hit else "VirusTotal의 여러 엔진이 입력 URL을 위험으로 분류했습니다."
        )
    elif status == "SUSPICIOUS" and any(
        item["scope"] == "exact_url" and item.get("detection_strength") == "single_engine"
        for item in detected
    ):
        message += " VirusTotal 엔진 1개가 입력 URL을 위험으로 분류했습니다."
    if not assessment["constraints_met"]:
        hours = request["conditions"].get("max_age_hours")
        message += (
            f" 최근 {hours}시간 이내라는 조건에 사용할 수 있는 관측 기록을 확보하지 못했습니다."
            if hours is not None else " 지정한 조회 범위에서 근거를 충분히 확보하지 못했습니다."
        )
    errors = {
        name: result["outcome"] for name, result in results.items()
        if not result["ok"] and result["outcome"] != "NO_RECORD"
    }
    search_error = (results.get("urlscan_history", {}).get("data") or {}).get("supplement_error")
    if search_error:
        errors["urlscan_history"] = search_error
    if any(code in {"MISSING_KEY", "AUTH_ERROR"} for code in errors.values()):
        message += " 일부 공급자의 API 키 또는 권한 설정을 확인해 주세요."
    elif errors:
        message += " 일부 공급자 조회가 실패해 확인 범위가 제한됩니다."
    if stop_reason == "REPLAN_LIMIT":
        message += " 재계획 상한에 도달해 조회를 마쳤습니다."
    actions = [
        "메시지의 링크 대신 해당 기관의 공식 앱이나 직접 확인한 주소를 사용하세요.",
        "비밀번호·인증번호·송금 요청은 발신자가 제공한 연락처와 다른 공식 경로로 확인하세요.",
    ]
    if status in {"KNOWN_RISK", "SUSPICIOUS"}:
        actions.insert(0, "확인이 끝날 때까지 링크 열기, 정보 입력, 송금, 앱 설치를 보류하세요.")
    return {
        "status": status, "message": message, "conditions": request["conditions"],
        "constraints_met": assessment["constraints_met"],
        "freshness_hours": assessment["freshness_hours"],
        "minimum_observed_at": assessment["minimum_observed_at"],
        "evidence": assessment["evidence"], "local_signals": request["signals"],
        "provider_comparison": assessment["provider_comparison"],
        "actions": actions,
        "tool_outcomes": {name: result["outcome"] for name, result in results.items()},
        "tool_errors": errors, "replans": replans, "stop_reason": stop_reason,
    }
