"""F3005: extract a target, freshness and scope from Korean requests."""

import re

from api_validation.__main__ import CheckError, host_for


URL = re.compile(r"https?://[^\s<>\x22'\x60]+", re.IGNORECASE)
PERIOD = re.compile(r"(최근\s*)?(\d+)\s*(시간|일)\s*(이내|내|동안|기록|결과|만)?")
FOLLOW_UP = re.compile(r"같은\s*(?:링크|주소|URL)|이전\s*(?:링크|주소|URL)|방금\s*(?:링크|주소|URL)", re.I)
ANALYZE = re.compile(r"사기|피싱|스미싱|의심|검사|분석|검증|위험|안전한|최근\s*\d+|이\s*(?:링크|주소|문자)|https?\s*:", re.I)
SIGNALS = {
    "인증정보 요구 표현": re.compile(r"인증번호|비밀번호|OTP", re.I),
    "금전 요구 표현": re.compile(r"송금|입금|계좌이체|수수료"),
    "긴급 조치 표현": re.compile(r"즉시|긴급|정지|만료|오늘까지"),
    "앱 설치·원격 제어 표현": re.compile(r"앱\s*설치|원격\s*제어|APK", re.I),
}
REQUEST_VERBS = r"(?:보내|알려|제출|전달|공유|회신|입력|요구|하세|부탁|바랍)(?!하지|지\s*마|지\s*않)"
TEXT_SIGNALS = {
    "개인정보 요구 표현": re.compile(rf"(?:주민등록번호|주민번호|계좌번호|카드번호|주소|신분증).{{0,25}}{REQUEST_VERBS}"),
    "인증정보 요구 표현": re.compile(rf"(?:인증\s*번호|비밀번호|OTP).{{0,25}}{REQUEST_VERBS}", re.I),
    "금전 요구 표현": re.compile(rf"(?:송금|입금|계좌이체|수수료).{{0,25}}{REQUEST_VERBS}|(?:즉시|지금|오늘까지).{{0,25}}(?:송금|입금)"),
    "긴급 조치 표현": re.compile(r"즉시|긴급|미이행|미처리|(?:계정|계좌|서비스).{0,12}(?:정지|만료|차단)"),
    "앱 설치·원격 제어 표현": SIGNALS["앱 설치·원격 제어 표현"],
}
PROVIDERS = {
    "google": r"(?:google\s+safe\s+browsing|구글\s*세이프\s*브라우징)",
    "virustotal": r"(?:virustotal|바이러스토탈)",
    "urlscan": r"urlscan(?:\.io)?",
}


def exclusive_provider(text):
    text = URL.sub("", text)
    matches = [
        name for name, pattern in PROVIDERS.items()
        if re.search(rf"\bonly\s+(?:use\s+)?{pattern}(?!\w)|{pattern}\s*만", text, re.I)
    ]
    return matches[0] if len(matches) == 1 else None


def analyze_request(text, memory, *, target_type="url"):
    targets = list(dict.fromkeys(match.group().rstrip(".,)>]}。”’") for match in URL.finditer(text)))
    content = URL.sub("", text)
    if target_type == "text":
        signals = [label for label, pattern in TEXT_SIGNALS.items() if pattern.search(content)]
        claimed_institution = re.search(r"검찰|경찰|금융감독원|국세청|은행|카드사|택배|고객센터", content)
        if claimed_institution and signals:
            signals.append("기관 사칭 의심 표현")
        if len(targets) != 1:
            return {"kind": "text_only", "signals": signals,
                    **({"issue": "MULTIPLE_URLS"} if targets else {})}
        try:
            host_for(targets[0])
        except CheckError:
            return {"kind": "text_only", "issue": "INVALID_OR_SENSITIVE_URL", "signals": signals}
        return {"kind": "analysis", "url": targets[0], "conditions": {}, "signals": signals}

    signals = [label for label, pattern in SIGNALS.items() if pattern.search(content)]
    period = next(
        (match for match in PERIOD.finditer(text) if match[1] or match[4]),
        None,
    )
    follow_up = not targets and (FOLLOW_UP.search(text) or (
        period and re.search(r"최근|이내|만", text)
    ))
    if not targets and not follow_up and not ANALYZE.search(text):
        return {"kind": "chat", "signals": []}
    if len(targets) > 1:
        return {"kind": "clarify", "issue": "MULTIPLE_URLS", "signals": signals}
    url = targets[0] if targets else memory.get("url") if follow_up else None
    if not url:
        return {"kind": "clarify", "issue": "URL_REQUIRED", "signals": signals}
    try:
        host_for(url)
    except CheckError:
        return {"kind": "clarify", "issue": "INVALID_OR_SENSITIVE_URL", "signals": signals}

    conditions = dict(memory.get("conditions", {})) if follow_up else {}
    if re.search(r"기간\s*제한\s*(?:없이|해제)", text):
        conditions.pop("max_age_hours", None)
    elif period:
        _, digits, unit, _ = period.groups()
        hours = int(digits) * (24 if unit == "일" else 1) if len(digits) <= 3 else 721
        if not 1 <= hours <= 720:
            return {"kind": "clarify", "issue": "INVALID_PERIOD", "signals": signals}
        conditions["max_age_hours"] = hours
    if re.search(r"도메인(?:도|\s*포함)", text):
        conditions["exact_only"] = False
    elif re.search(r"정확(?:히|한)?\s*(?:URL|주소)|URL만|도메인\s*제외", text, re.I):
        conditions["exact_only"] = True
    retained = memory.get("signals", []) if follow_up else []
    return {
        "kind": "analysis", "url": url, "conditions": conditions,
        "signals": list(dict.fromkeys([*retained, *signals])),
    }
