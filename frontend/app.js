import {mountInvestigation} from "/assets/investigation.js?v=3";

const $ = (id) => document.getElementById(id);
const el = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
};

const tools = {
  google_safe_browsing: "Google Safe Browsing",
  virustotal_url: "VirusTotal · URL",
  virustotal_domain: "VirusTotal · 도메인",
  urlscan_history: "urlscan.io · 공개 기록",
};
const nodes = {
  analyze: "사용자 요청 분석", plan: "작업 계획 생성", execute: "외부 Tool 실행",
  judge: "위험 근거 판단", replan: "재계획 검토", respond: "예방 행동 응답 생성",
};
const codes = {
  MATCH: "위협 유형 일치", NO_MATCH: "알려진 위협 목록 미일치", REPORT: "분석 보고서 확인",
  CANDIDATES: "공개 관측 기록 확인", NO_CANDIDATES: "공개 관측 기록 없음",
  NO_RECORD: "등록된 보고서 없음", INCOMPLETE_REPORT: "보고서 일부 누락",
  TIMEOUT: "응답 시간 초과", NETWORK_ERROR: "네트워크 연결 실패",
  AUTH_ERROR: "공급자 인증 실패", MISSING_KEY: "공급자 설정 누락",
  RATE_LIMIT: "공급자 요청 한도에 도달", UPSTREAM_ERROR: "공급자 응답 오류",
  INVALID_RESPONSE: "공급자 응답 해석 실패",
  LLM_TIMEOUT: "모델 응답 시간 초과", LLM_TOOL_CALL_MISSING: "모델이 실행 결정을 반환하지 않음",
  LLM_OUTPUT_TRUNCATED: "모델 응답이 중간에 종료됨", LLM_OUTPUT_FILTERED: "모델 응답이 필터링됨",
  LLM_UNSUPPORTED_CALL_FORMAT: "지원하지 않는 모델 응답 형식", LLM_UNKNOWN_TOOL: "제공하지 않은 Tool 선택",
  LLM_INVALID_ARGUMENTS: "모델의 Tool 인자 형식 불일치",
  LLM_CONTEXT_SCHEMA_INVALID: "문맥 분석 응답 형식 불일치",
  LLM_CONTEXT_REFERENCE_INVALID: "문맥 분석에서 잘못된 원문 번호를 선택함",
  LLM_NOT_CONFIGURED: "AI 연결 설정 없음", LLM_NOT_ENOUGH_TEXT: "분석할 문자 내용 부족",
  REPLAN_LIMIT: "재계획 한도 도달", EVIDENCE_COLLECTED: "판단 근거 확보",
  NO_MORE_ALTERNATIVES: "추가 조회 수단 없음", COVERAGE_INCOMPLETE: "조회 범위에 추가 근거 필요",
  CONSTRAINTS_UNMET: "요청 조건을 충족하는 근거 부족",
  LLM_NO_USEFUL_ALTERNATIVE: "모델이 추가 조회의 이점이 없다고 판단",
  WORKER_REQUESTED_CHANGE: "Worker가 대체 조회를 요청",
  AUDIT_ANOMALY: "로깅 Agent가 실행 검토를 요청",
  UNPLANNED_TOOL: "계획에 없는 Tool 호출", DUPLICATE_CALL: "동일 인자 반복 호출",
  PLAN_ORDER: "계획과 작업 순서 불일치", RETRY_LIMIT: "Worker 재시도 한도 초과",
  FIXED_ARGUMENT_CHANGED: "고정 인자 변경", UNDECLARED_RETRY: "허용되지 않은 재시도",
  MISSING_OR_EXTRA_ATTEMPT: "실행 기록과 결과 불일치",
  complete: "작업 완료", retry_same_tool: "같은 Tool 재시도",
  skip_task: "작업 건너뜀", request_new_plan: "Planner에 계획 변경 요청",
  UNAVAILABLE_CONFIGURATION: "공급자 설정 확인 필요",
  rules_fallback: "규칙 기반 분석으로 전환", continue: "확보한 근거로 계속 진행", propagated: "실행 중단",
  known_threat_lookup: "알려진 위협 목록 확인", exact_url_report: "URL 분석 보고서 확인",
  host_reputation: "도메인 평판 확인", recent_scan_history: "최근 공개 관측 기록 확인",
  alternative_evidence: "대체 근거 확인",
};
const statuses = {
  KNOWN_RISK: ["위험 기록이 있어요", "risk"],
  SUSPICIOUS: ["의심스러운 점이 있어요", "warn"],
  NO_KNOWN_MATCH: ["조회한 목록에 위험 기록이 없어요", "unmatched"],
  INSUFFICIENT_EVIDENCE: ["안전한지 확인하기 어려워요", "neutral"],
  GENERAL: ["안내", ""],
};
const scopes = {exact_url: "입력 URL", url_expression: "Google 비교 패턴", same_host: "같은 호스트",
  host_search: "호스트 검색", reported_url_mismatch: "보고서 URL 불일치"};
const stamp = new Intl.DateTimeFormat("ko-KR", {dateStyle: "medium", timeStyle: "medium"});
const when = (value) => value && !Number.isNaN(Date.parse(value)) ? stamp.format(new Date(value)) : "시각 미확인";
const label = (code) => codes[code] || code;
const toolName = (name) => tools[name] || name;

async function api(path, method = "GET", data) {
  let response;
  try {
    response = await fetch(path, {
      method, credentials: "same-origin",
      ...(data === undefined ? {} : {headers: {"Content-Type": "application/json"}, body: JSON.stringify(data)}),
    });
  } catch {
    throw new Error("서버에 연결할 수 없습니다. 서버가 실행 중인지 확인하고 다시 시도하세요.");
  }
  if (response.status === 204) return null;
  const payload = await response.json().catch(() => null);
  if (response.ok && payload) return payload;
  const code = payload?.error?.code;
  if (response.status === 401) {
    const error = new Error("유효한 세션이 없습니다. 위험 분석에서 요청을 보내 세션을 시작하세요. 만료된 세션 오류가 계속되면 이 사이트의 쿠키를 지우고 다시 시도하세요.");
    error.code = code;
    throw error;
  }
  const error = new Error(payload?.error?.message || "서버 응답을 처리할 수 없습니다.");
  error.code = code;
  throw error;
}

function feedback(node, message = "", kind = "") {
  node.className = kind ? `feedback ${kind}` : "feedback";
  node.textContent = message;
  node.hidden = !message;
}

function empty(node, title, detail = "") {
  const box = el("div", null, "empty");
  box.append(el("strong", title));
  if (detail) box.append(el("p", detail));
  node.replaceChildren(box);
}

function button(caption, handler, kind = "secondary") {
  const control = el("button", caption, kind);
  control.type = "button";
  control.addEventListener("click", handler);
  return control;
}

function actionList(steps) {
  const list = el("ol", null, "actions");
  for (const step of steps) list.append(el("li", step));
  return list;
}

function resultPanel(title, variant = "") {
  const section = el("section", null, variant ? `result-section ${variant}` : "result-section");
  if (title) section.append(el("h2", title));
  return section;
}

function recentEvidenceSummary(analysis) {
  const hours = analysis.conditions?.max_age_hours;
  if (hours == null || analysis.constraints_met !== false || analysis.status !== "INSUFFICIENT_EVIDENCE") return null;

  const threshold = Date.parse(analysis.minimum_observed_at);
  const previous = analysis.evidence
    .filter((item) => item.tool === "virustotal_url" && item.scope === "exact_url"
      && item.outcome === "REPORT" && Date.parse(item.observed_at) < threshold
      && Number.isInteger(item.engine_counts?.malicious))
    .sort((a, b) => Date.parse(b.observed_at) - Date.parse(a.observed_at))[0];
  if (previous) {
    return `최근 ${hours}시간 기록은 없고, 이전 보고서에서는 악성 탐지가 ${previous.engine_counts.malicious}건이었습니다. 현재 안전 여부는 확인되지 않았습니다.`;
  }
  const googleResult = analysis.tool_outcomes?.google_safe_browsing === "NO_MATCH"
    ? "Google의 위험 목록에 이 링크는 없었어요. " : "";
  return `${googleResult}최근 ${hours}시간 기록은 확인하지 못해서, 지금 안전한지는 알 수 없어요.`;
}

function followUpPanel(runId, initial) {
  const section = resultPanel("쉴디의 추가 확인");
  const body = el("div", null, "follow-up-body");
  const history = el("ol", null, "follow-up-history");
  history.hidden = true;
  const current = el("div", null, "follow-up-current");
  const progress = el("p", null, "row-hint");
  progress.setAttribute("aria-live", "polite");
  body.append(el("p", "요구받은 정보의 종류만 선택해 주세요. 실제 번호나 사진은 필요 없어요.", "row-hint"),
    history, current, progress);
  section.append(body);

  function show(state, focus = false) {
    const question = state.question;
    const heading = el("h3", question?.prompt ?? (state.status === "skipped" ? "추가 확인을 건너뛰었어요" : "답변을 반영한 안내"));
    heading.tabIndex = -1;
    current.replaceChildren(heading);
    if (state.actions.length) {
      if (question) current.append(el("p", "지금 먼저 할 일", "follow-up-action-title"));
      current.append(actionList(state.actions));
    }
    if (!question) {
      current.append(el("p", "처음 분석한 결과도 이 화면에서 계속 확인할 수 있어요.", "row-hint"));
    } else {
      const choices = el("div", null, "follow-up-options");
      const submit = async (answer, caption) => {
        const controls = choices.querySelectorAll("button");
        controls.forEach((control) => { control.disabled = true; });
        progress.textContent = "답변을 반영하고 있어요.";
        try {
          const next = await api(`/api/chat/${encodeURIComponent(runId)}/follow-up`, "POST",
            {question_id: question.id, answer});
          if (answer !== "skip") {
            const item = el("li");
            item.append(el("span", question.prompt), el("strong", caption));
            history.append(item);
            history.hidden = false;
          }
          progress.textContent = "";
          show(next, true);
        } catch (error) {
          progress.textContent = error.message;
          if (error.code !== "FOLLOW_UP_UNAVAILABLE" && error.code !== "SESSION_REQUIRED") {
            controls.forEach((control) => { control.disabled = false; });
          }
        }
      };
      for (const option of question.options) {
        choices.append(button(option.label, () => submit(option.id, option.label)));
      }
      choices.append(button("여기서 마치기", () => submit("skip"), "follow-up-skip"));
      current.append(choices);
    }
    if (focus && body.isConnected && !body.closest("[hidden]")) heading.focus();
  }

  show(initial);
  return section;
}

function messageContextPanel(messageContext, mode) {
  const titles = {text: "AI 문자 문맥 분석", url: "AI URL 문맥 분석", call: "AI 통화 문맥 분석"};
  const review = resultPanel(titles[mode]);
  if (messageContext.status === "rules_only") {
    const reasons = {
      LLM_TIMEOUT: "AI 응답이 늦어 맥락을 끝까지 살펴보지 못했어요.",
      LLM_NETWORK_ERROR: "AI 서버에 연결할 수 없었어요.",
      LLM_NOT_CONFIGURED: "현재 AI 서버를 사용할 수 없어요.",
      LLM_NOT_ENOUGH_TEXT: mode === "url"
        ? "주소만으로는 받은 상황을 알기 어려워요. 링크를 어디서 받았고 무엇을 요구했는지 적어 주세요."
        : "AI가 살펴볼 내용이 충분하지 않았어요.",
      LLM_RATE_LIMIT: "AI 요청이 몰려 지금은 문맥을 살펴보지 못했어요.",
      LLM_CONTEXT_SCHEMA_INVALID: "AI 응답을 결과로 표시할 수 있는 형식이 아니었어요.",
      LLM_CONTEXT_REFERENCE_INVALID: "AI가 짚은 내용의 원문 근거를 확인할 수 없었어요.",
    };
    review.append(el("p", `${reasons[messageContext.reason] ?? "AI 문맥 분석을 마치지 못했어요."} 위의 기본 분석 결과와 예방 안내는 확인할 수 있어요.`));
  } else {
    review.append(el("strong", "AI 문맥 분석 완료", "result-status unmatched"));
    review.append(el("p", {
      text: "보내주신 문자 표현을 살펴봤어요. 실제 발신자와 요청의 진위는 공식 연락처로 확인해 주세요.",
      url: "링크를 받은 상황을 살펴봤어요. 주소에 대한 보안 조회 결과는 아래에서 확인할 수 있어요.",
      call: "선택한 통화 상황을 살펴봤어요. 실제 상대의 신원은 기존에 알던 번호나 공식 연락처로 확인해 주세요.",
    }[mode], "row-hint"));
    for (const [title, entries] of [["입력에서 확인한 내용", messageContext.facts], ["확인해 볼 정황", messageContext.signals]]) {
      if (!entries.length) continue;
      const list = el("ul", null, "facts");
      for (const entry of entries) {
        const item = el("li", null, "fact");
        item.append(el("strong", entry.label),
          el("span", entry.source === "llm" ? " · AI 검토" : " · 규칙 확인", "row-hint"),
          el("blockquote", entry.quote, "message-quote"));
        list.append(item);
      }
      review.append(el("h3", title), list);
    }
    if (!messageContext.signals.length) review.append(el("p", "문맥에서 추가로 짚을 의심 정황을 찾지 못했어요."));
    for (const [title, entries] of [["아직 알 수 없는 점", messageContext.unknowns],
      ["추가 확인 사항", messageContext.checks], ["권장 예방 행동", messageContext.actions]]) {
      if (!entries?.length) continue;
      const list = el("ul");
      list.append(...entries.map((entry) => el("li", entry)));
      review.append(el("h3", title), list);
    }
  }
  return review;
}

function riskJudgmentPanel(verdict, nextAction) {
  const summary = resultPanel("최종 위험 판단", "guidance");
  const [status, style] = statuses[verdict] ?? statuses.INSUFFICIENT_EVIDENCE;
  const indicator = el("span", {risk: "⚠", warn: "!", unmatched: "ⓘ", neutral: "—"}[style] ?? "ⓘ", "status-icon");
  indicator.setAttribute("aria-hidden", "true");
  const badge = el("strong", null, `result-status result-message ${style}`);
  badge.append(indicator, el("span", status));
  summary.append(badge);
  if (nextAction) {
    const next = el("div", null, "next-action");
    const image = el("img", null, "advice-mascot");
    image.src = "/assets/shieldy-transparent.png";
    image.alt = "";
    image.width = 55;
    image.height = 69;
    const advice = el("div");
    advice.append(el("h3", "쉴디의 예방 안내"), el("p", nextAction));
    const caution = {
      KNOWN_RISK: "알려진 위험 근거를 확인했어요.",
      SUSPICIOUS: "의심스러운 점이 있어요. 공식 연락처로 따로 확인하세요.",
      NO_KNOWN_MATCH: "위험 기록이 없어도 링크나 메시지가 안전하다고 단정할 수는 없어요.",
      INSUFFICIENT_EVIDENCE: "지금은 안전 여부를 판단할 만큼 정보가 충분하지 않아요.",
    }[verdict];
    if (caution) advice.append(el("p", caution, "row-hint"));
    next.append(image, advice);
    summary.append(next);
  }
  return summary;
}

function preventionPanel(actions, save) {
  const guidance = resultPanel("추가 예방 행동");
  if (actions.length) guidance.append(actionList(actions));
  if (save) guidance.append(button("예방 계획에 저장", save, "primary"));
  return guidance;
}

function renderResult(result) {
  const analysis = result.analysis;
  const area = $("analysis-result");
  const recentSummary = recentEvidenceSummary(analysis);
  const [firstAction, ...otherActions] = analysis.actions;
  const checkOfficialChannel = ["NO_KNOWN_MATCH", "INSUFFICIENT_EVIDENCE"].includes(analysis.status);
  const nextAction = checkOfficialChannel
    ? "링크를 바로 누르지 말고, 보낸 곳의 공식 앱이나 웹사이트에 직접 들어가 같은 안내가 있는지 확인하세요. 확인 전에는 비밀번호나 인증번호를 입력하지 마세요."
    : firstAction;
  const summary = riskJudgmentPanel(analysis.status, nextAction);
  if (result.status === "partial") {
    summary.append(el("p", "일부 조회를 마치지 못했어요. 확인한 내용은 아래에서 볼 수 있어요.", "row-hint"));
  }
  const panels = [summary];
  if (result.follow_up) panels.push(followUpPanel(result.run_id, result.follow_up));
  const remainingActions = checkOfficialChannel ? analysis.actions : otherActions;
  if (remainingActions.length || result.plan_draft) {
    panels.push(preventionPanel(remainingActions,
      result.plan_draft ? () => openPlanEditor({draft: result.plan_draft}) : null));
  }
  const context = resultPanel("판단 근거 요약");
  context.append(el("p", recentSummary ?? analysis.message));
  if (analysis.local_signals.length) {
    const origin = analysis.text_assessment ? "문자 표현" : "입력 내용";
    context.append(el("p", `${origin}의 의심 정황: ${analysis.local_signals.join(" · ")}`, "result-message"));
  }
  if (analysis.text_assessment?.url_lookup === "not_attempted") {
    context.append(el("p", "문자 내용을 살펴봤어요. 외부 링크 조회는 하지 않았어요.", "row-hint"));
  }
  if (result.status === "partial") {
    const parts = [];
    if (analysis.llm_error) parts.push(`LLM 조회 실패: ${label(analysis.llm_error)} (${analysis.llm_error})`);
    for (const [name, value] of Object.entries(analysis.tool_errors)) parts.push(`${toolName(name)}: ${label(value)}`);
    if (parts.length) context.append(el("p", parts.join(" / "), "feedback warn"));
  }
  panels.push(context);
  const messageContext = analysis.text_assessment?.context ?? analysis.message_context;
  if (messageContext) panels.push(messageContextPanel(messageContext, analysis.text_assessment ? "text" : "url"));
  {
    const comparison = resultPanel("보안 서비스별 결과");
    const comparisons = {
      different: "공급자별 검사 결과가 다릅니다. 각 결과의 출처와 관측 범위를 확인하세요.",
      agreement: "두 공급자에서 입력 URL에 대한 위험 신호를 확인했습니다.",
      scope_differs: "공급자별 검사 범위가 다릅니다. 입력 URL·호스트·비교 패턴을 구분해 보세요.",
    };
    if (analysis.provider_comparison) {
      comparison.append(el("p", comparisons[analysis.provider_comparison], "feedback warn"));
    }
    const outcomes = el("ul", null, "facts");
    for (const name of Object.keys(tools)) {
      const outcome = analysis.tool_outcomes[name];
      const error = analysis.tool_errors[name];
      const row = el("li", null, "fact");
      if (!outcome || outcome === "MISSING_KEY" || outcome === "UNAVAILABLE_CONFIGURATION") {
        row.append(el("strong", toolName(name)), el("p", error || outcome
          ? `조회 결과 없음 · ${label(error ?? outcome)}` : "호출하지 않았어요.", "row-hint"));
        outcomes.append(row);
        continue;
      }
      const outcomeText = name === "google_safe_browsing" && outcome === "NO_MATCH"
        ? "위험 목록에 없음" : label(outcome);
      row.append(el("strong", `${toolName(name)} · ${outcomeText}`), el("div", outcome, "tag"));
      for (const record of analysis.evidence.filter((entry) => entry.tool === name)) {
        const scope = scopes[record.scope] ?? record.scope;
        row.append(el("p", `${scope} · 관측 시각: ${when(record.observed_at)}`, "row-hint"));
      }
      const item = analysis.evidence.find((entry) => entry.tool === name && entry.reported_engines != null);
      if (item) {
        const strength = {single_engine: "단일 엔진 탐지", multiple_engines: "여러 엔진 탐지"};
        row.append(el("p", `탐지 엔진 ${item.engine_counts?.malicious ?? 0}개 · 응답 분류 합계 ${item.reported_engines}건`, "row-hint"));
        if (item.detection_strength) row.append(el("p", strength[item.detection_strength], "tag"));
        row.append(el("p", Object.entries(item.engine_counts).map(([key, count]) => `${key}: ${count}`).join(" · "), "row-hint"));
      }
      if (name === "google_safe_browsing" && outcome === "NO_MATCH") {
        row.append(el("p", "Google의 위험 목록에 이 링크는 없었어요. 목록에 없다고 해서 안전하다는 뜻은 아니에요.", "row-hint"));
      }
      outcomes.append(row);
    }
    comparison.append(outcomes);
    panels.push(comparison);
  }
  const evidence = el("details", null, "result-section evidence-details");
  evidence.append(el("summary", "상세 근거 및 제외 사유"));
  const observations = resultPanel("관측 시각과 조회 조건");
  const hours = analysis.conditions?.max_age_hours;
  if (hours != null) {
    observations.append(el("p", `요청: 최근 ${hours}시간 · 전체 조건 ${analysis.constraints_met ? "충족" : "미충족"} · 기준 시각: ${when(analysis.minimum_observed_at)}`, "row-hint"));
  }
  if (analysis.conditions?.exact_only) observations.append(el("p", "요청 범위: 입력 URL과 정확히 일치하는 기록", "row-hint"));
  if (analysis.evidence.length) {
    const facts = el("ul", null, "facts");
    const dateList = el("ul", null, "facts");
    const search = analysis.evidence.find((item) => item.searched_days != null);
    if (search) {
      const limit = search.searched_days < search.requested_search_days
        ? ` · 공급자 한도: 요청 ${search.requested_search_days}일 중 ${search.searched_days}일` : "";
      const remainder = search.candidate_more_available ? " · 미조회 페이지 있음" : "";
      const condition = hours == null ? "" : ` · 후보 판단 기준: 최근 ${hours}시간`;
      observations.append(el("p", `urlscan.io 공개 기록: 최근 ${search.searched_days}일, ${search.candidate_pages}페이지${limit}${condition}${remainder}`, "row-hint"));
    }
    for (const item of analysis.evidence) {
      const row = el("li", null, "fact");
      const scope = item.supplemental_search ? "추가 후보 조회" : scopes[item.scope] || item.scope;
      const period = hours == null ? "" : ` · 요청 기간: ${item.observed_at ? (item.freshness_met ? "충족" : "미충족") : "검증 불가"}`;
      dateList.append(el("li", `${item.source} · ${scope} · 관측: ${when(item.observed_at)}${period}`, "fact"));
      row.append(el("strong", `${item.source} · ${scope}`));
      row.append(el("div", item.eligible ? "검증 근거로 사용 가능" : "검증 근거에서 제외", "row-hint"));
      if (item.exclusion_reasons?.length) {
        const reasons = el("ul", null, "row-hint");
        for (const reason of item.exclusion_reasons) {
          reasons.append(el("li", reason.code === "API_ERROR" ? `${reason.message} (${label(item.outcome)})` : reason.message));
        }
        row.append(reasons);
      }
      if (item.threat_types?.length) row.append(el("div", item.threat_types.join(" · "), "tag"));
      if (item.scan_id) row.append(el("div", `스캔 ID: ${item.scan_id}`, "tag"));
      if (item.supplemental_candidate_id) {
        row.append(el("p", "정확 URL 보강 후보 · VirusTotal 기존 보고서", "row-hint"));
      }
      facts.append(row);
    }
    observations.append(dateList);
    evidence.append(facts);
  } else {
    observations.append(el("p", "표시할 외부 관측 시각이 없어요.", "row-hint"));
    evidence.append(el("p", "표시할 외부 관측 근거가 없습니다.", "row-hint"));
  }
  panels.push(observations, evidence);
  area.replaceChildren(...panels);
  area.hidden = false;
}

function describeEvent({event_type: type, data: d}) {
  switch (type) {
    case "run.started": return ["실행 시작", ""];
    case "run.finished": return [d.status === "completed" ? "실행 완료" : "실행 실패", d.replans == null ? "" : `재계획 ${d.replans}회`];
    case "node.entered": return [`${nodes[d.node] || d.node} · 시작`, ""];
    case "node.finished": return [`${nodes[d.node] || d.node} · ${d.status === "completed" ? "완료" : "실패"}`, ""];
    case "tool.requested": return [`${toolName(d.tool)} · 호출`, d.days == null ? "" : `조회 기간: 최근 ${d.days}일`];
    case "tool.finished": return [`${toolName(d.tool)} · ${d.ok ? "응답" : "제한 또는 실패"}`,
      [label(d.outcome), d.outcome, d.duration_ms == null ? "" : `${d.duration_ms} ms`].filter(Boolean).join(" · ")];
    case "llm.decision": return [d.stage === "message_context" ? "AI 맥락 분석"
      : tools[d.choice] ? `LLM Tool 선택 · ${toolName(d.choice)}` : "LLM 실행 판단",
      [tools[d.choice] ? "" : d.choice, d.reason ? label(d.reason) : ""].filter(Boolean).join(" · ")];
    case "message_context.finished": return [
      {analyzed: "AI 맥락 분석 완료", cache_hit: "이전 문맥 분석 결과 재사용", rules_only: "문맥 분석 대신 규칙 사용"}[d.status],
      [d.reason ? label(d.reason) : "", d.http_status ? `HTTP ${d.http_status}` : "",
        d.duration_ms == null ? "" : `${d.duration_ms} ms`].filter(Boolean).join(" · "),
    ];
    case "replan.decided": return [d.performed ? "재계획 적용" : "재계획 없이 종료",
      [label(d.reason), d.tool ? toolName(d.tool) : "", d.source === "llm" ? "LLM 선택" : d.source === "rules" ? "규칙 판단" : ""].filter(Boolean).join(" · ")];
    case "response.generated": return ["예방 행동 응답 생성", statuses[d.status]?.[0] || d.status];
    case "error.handled": return ["오류 처리", [label(d.code), label(d.handling)].filter(Boolean).join(" · ")];
    case "planner.task": return [`Planner 작업 #${d.task_id} · ${toolName(d.tool)}`,
      `URL 고정${d.days == null ? "" : ` · ${d.days}일${d.fixed_days ? " (고정)" : ""}`}`];
    case "worker.attempt": return [`Worker 작업 #${d.task_id} · ${d.attempt}번째 실행`, toolName(d.tool)];
    case "worker.decision": return [`Worker · ${label(d.action)}`,
      [d.llm_called ? "LLM 호출" : "규칙 처리", d.outcome ? label(d.outcome) : ""].filter(Boolean).join(" · ")];
    case "audit.checked": return [
      d.status === "verified" ? "로깅 Agent · 실행 검증 완료" : "로깅 Agent · 검토 필요",
      [label(d.code), d.request_plan_change ? "재계획 요청" : "", d.llm_called ? "LLM 검토" : ""].filter(Boolean).join(" · "),
    ];
    default: return [type, ""];
  }
}

function renderTimeline(target, events, showRaw = false) {
  if (!events.length) { empty(target, "실행 기록 없음"); return; }
  const list = el("ol", null, "timeline");
  for (const event of [...events].sort((a, b) => a.sequence - b.sequence)) {
    const [title, detail] = describeEvent(event);
    const entry = el("li");
    const hasError = event.event_type === "error.handled"
      || event.event_type === "tool.finished" && event.data.ok === false
      || event.event_type === "audit.checked" && event.data.status === "anomaly";
    if (hasError) entry.classList.add("event-error");
    else if (event.event_type === "replan.decided" && event.data.performed) entry.classList.add("event-replan");
    const time = el("time", `#${event.sequence} · ${when(event.occurred_at)}`);
    time.dateTime = event.occurred_at;
    entry.append(time, el("strong", title));
    if (detail) entry.append(el("p", detail, "event-meta"));
    if (showRaw) {
      const raw = el("details", null, "raw-event");
      raw.append(el("summary", "원본 이벤트"), el("pre", JSON.stringify(event, null, 2)));
      entry.append(raw);
    }
    list.append(entry);
  }
  target.replaceChildren(list);
}

function showDecisions(target, decisions) {
  const selected = decisions.filter((decision) => decision.choices.some((choice) => tools[choice]));
  if (!selected.length) return;
  const sources = el("section");
  sources.append(el("h3", "Tool 선택과 판단 출처"));
  const list = el("ul", null, "actions");
  for (const decision of selected) {
    const task = decision.stage === "replan" ? "재계획" : "초기 계획";
    const names = decision.choices.filter((choice) => tools[choice]).map(toolName);
    list.append(el("li", `${task} · ${decision.source === "llm" ? "LLM 선택" : "규칙 선택"}: ${names.join(" → ")}`));
  }
  sources.append(list);
  target.prepend(sources);
}

const form = $("analysis-form");
const message = $("message");
const analysisInputs = {
  url: ["URL 분석", "의심스러운 공개 링크를 입력하세요.", "예: https://example.com/"],
  text: ["메신저 분석", "의심스러운 문자나 메신저 내용을 붙여 넣으세요.", "예: 앱 설치를 요구하는 의심스러운 문자"],
};
const analysisDrafts = {url: "", text: ""};
const analysisOptIns = {url: false, text: false};
let analysisViewVersion = 0;
let investigation;
message.addEventListener("input", () => {
  $("counter").textContent = `${message.value.length} / 4000`;
  message.removeAttribute("aria-invalid");
});

function updateContextOptions() {
  const url = form.elements.target_type.value === "url";
  $("url-context-note").hidden = !url || !form.elements.context_analysis.checked;
  $("context-privacy").textContent = url
    ? "링크 주소와 일부 민감정보를 가린 상황 설명을 외부 AI에 보냅니다. 주소 확인은 별도로 진행합니다."
    : "일부 민감정보와 링크를 가린 문자를 외부 AI에 보냅니다. 이름, 연락처 등 개인정보는 입력 전에 지워 주세요.";
}
form.elements.context_analysis.addEventListener("change", updateContextOptions);

function selectAnalysisInput(type) {
  const target = form.elements.target_type;
  if (target.value !== type) {
    analysisDrafts[target.value] = message.value;
    analysisOptIns[target.value] = form.elements.context_analysis.checked;
    target.value = type;
    form.elements.context_analysis.checked = analysisOptIns[type];
    message.value = analysisDrafts[type];
    message.dispatchEvent(new Event("input"));
    analysisViewVersion += 1;
    investigation?.dispose();
    investigation = undefined;
    $("analysis-result").hidden = true;
    feedback($("analysis-feedback"));
    empty($("trace"), "아직 실행 기록이 없습니다.");
  }
  const [title, description, placeholder] = analysisInputs[type];
  $("input-title").textContent = title;
  $("input-description").textContent = description;
  message.placeholder = placeholder;
  updateContextOptions();
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = $("analyze");
  if (submit.disabled) return;
  const input = message.value.trim();
  if (!input) {
    feedback($("analysis-feedback"), "분석할 URL 또는 메시지를 입력하세요.", "error");
    message.setAttribute("aria-invalid", "true");
    message.focus();
    return;
  }
  submit.disabled = true;
  investigation?.dispose();
  investigation = undefined;
  $("analysis-result").hidden = true;
  feedback($("analysis-feedback"), "분석 요청을 처리 중입니다. 완료 후 검증 결과를 표시합니다.");
  const trace = $("trace");
  const version = analysisViewVersion;
  empty(trace, "서버 응답 대기 중", "실행 타임라인은 분석 응답을 받은 뒤 조회합니다.");
  try {
    const target = form.elements.target_type.value;
    const optedIn = form.elements.context_analysis.checked;
    const note = target === "url" ? form.elements.context_note.value.trim() : "";
    const data = await api("/api/chat", "POST", {
      message: input, target_type: target,
      ...(optedIn ? {context_analysis: true, ...(note ? {context_note: note} : {})} : {}),
    });
    if (version !== analysisViewVersion) return;
    renderResult(data);
    investigation = mountInvestigation($("analysis-investigation"), data, target, {
      statuses, scopes, toolName, label, when, describeEvent, save: (draft) => openPlanEditor({draft}),
    });
    feedback($("analysis-feedback"), data.status === "partial" ? "분석 완료 · 일부 조회 실패" : "분석 완료", data.status === "partial" ? "warn" : "");
    try {
      const log = await api(`/api/logs/${encodeURIComponent(data.run_id)}`);
      if (version !== analysisViewVersion) return;
      investigation.update(log.events);
      renderTimeline(trace, log.events);
    } catch (error) {
      if (version !== analysisViewVersion) return;
      investigation.update(null, error.code === "LOG_NOT_FOUND" ? "저장된 실행 로그 없음" : "실행 로그 조회 실패");
      empty(trace, error.code === "LOG_NOT_FOUND" ? "저장된 실행 로그 없음" : "실행 로그 조회 실패",
        error.code === "LOG_NOT_FOUND" ? "분석 결과는 위에서 확인할 수 있어요." : error.message);
    }
    showDecisions(trace, data.analysis.decisions);
  } catch (error) {
    if (version !== analysisViewVersion) return;
    feedback($("analysis-feedback"), error.message, "error");
    empty(trace, "표시할 실행 기록 없음");
  } finally {
    submit.disabled = false;
  }
});

function callGuidance({contact, request, verification, sent}) {
  const confirmContact = {
    family: "통화를 끊고, 원래 저장해 둔 가족이나 지인의 번호로 직접 전화하세요.",
    work: "기존에 알고 있던 사내 번호나 거래처 대표번호로 요청을 확인하세요. 송금이나 계좌 변경은 내부 승인 절차를 거치세요.",
    agency: "통화를 끊고 은행이나 기관의 공식 앱 또는 홈페이지에서 대표번호를 찾아 직접 전화하세요.",
    other: "상대가 알려준 번호 대신, 이전에 저장한 번호나 공식 대표번호로 직접 확인하세요.",
  };
  const handleRequest = {
    transfer: "확인되지 않은 계좌로 송금하거나 거래처 계좌를 변경하지 마세요.",
    code: "인증번호나 비밀번호는 통화에서 알려주지 마세요.",
    id_photo: "신분증 사진을 보내기 전에 원래 알던 번호나 공식 연락처로 요청을 확인하세요.",
    app: "상대가 보내 준 앱을 설치하거나 원격 제어를 허용하지 마세요.",
  };
  const actions = [];
  if (sent) actions.push("추가 송금을 멈추고, 송금에 사용한 은행이나 결제 서비스의 공식 고객센터에 즉시 연락해 사기 의심 거래라고 알려주세요.");
  if (handleRequest[request]) actions.push(handleRequest[request]);
  if (verification !== "yes" || contact === "work") actions.push(confirmContact[contact]);
  if (!actions.length) actions.push("새로운 요청이 들어오면 원래 알던 연락처로 다시 확인한 뒤 진행하세요.");
  const title = sent ? "이미 송금했다면 지금 바로 연락하세요"
    : verification === "denied" ? "사칭이 의심돼요"
      : verification === "no" ? "먼저 상대를 따로 확인하세요" : "요청에 응하기 전 확인하세요";
  return {title, actions};
}

const callForm = $("call-form");
callForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = $("check-call");
  if (submit.disabled) return;
  const input = new FormData(callForm);
  const {title, actions} = callGuidance(Object.fromEntries(input));
  const panel = resultPanel(title, "guidance");
  const heading = panel.querySelector("h2");
  heading.id = "call-result-title";
  heading.tabIndex = -1;
  panel.append(actionList(actions));
  const status = el("p", "선택한 상황에서 의심스러운 점을 확인하고 있어요.", "row-hint");
  status.setAttribute("role", "status");
  panel.append(status);
  const output = $("call-result");
  output.replaceChildren(panel);
  output.hidden = false;
  heading.focus();
  submit.disabled = true;

  const selected = (name) => callForm.elements[name].selectedOptions[0].textContent;
  const description = `${selected("channel")}에서 상대가 ${selected("contact")}이라고 했어요. `
    + (input.get("request") === "other" ? "상대가 무엇을 요구했는지는 잘 모르겠어요. " : `${selected("request")} 요청을 받았어요. `)
    + `${selected("verification")}.`
    + (input.has("sent") ? " 이미 돈을 보냈어요." : "");
  try {
    const note = input.get("context_note").trim();
    const result = await api("/api/chat", "POST", {
      message: description, target_type: "text", context_analysis: input.has("context_analysis"),
      ...(note ? {context_note: note} : {}),
      call_context: {request: input.get("request"), verification: input.get("verification"), already_sent: input.has("sent")},
    });
    const {analysis} = result;
    const [firstAction, ...otherActions] = actions;
    const summary = riskJudgmentPanel(analysis.status, firstAction);
    const resultTitle = summary.querySelector("h2");
    resultTitle.id = "call-result-title";
    resultTitle.tabIndex = -1;
    const restoreFocus = document.activeElement === heading;
    const panels = [summary];
    if (result.follow_up) panels.push(followUpPanel(result.run_id, result.follow_up));
    panels.push(preventionPanel(otherActions, () => {
      openPlanEditor(result.plan_draft ? {draft: result.plan_draft} : {actions});
    }));
    const details = resultPanel("판단 근거 요약");
    status.textContent = analysis.local_signals.length
      ? `입력한 상황에서 확인한 의심 신호: ${analysis.local_signals.join(" · ")}`
      : "입력한 내용만으로 사칭인지 판단하기 어려워요.";
    details.append(status);
    panels.push(details);
    if (analysis.text_assessment?.context) panels.push(messageContextPanel(analysis.text_assessment.context, "call"));
    output.replaceChildren(...panels);
    if (restoreFocus && !output.closest("[hidden]")) resultTitle.focus();
  } catch {
    status.textContent = "추가 분석을 불러오지 못했어요. 위의 대응 방법을 먼저 확인하세요.";
  } finally {
    submit.disabled = false;
  }
});

const dialog = $("plan-dialog");
const planForm = $("plan-form");
const scheduleFields = ["execution_date", "start_time", "end_time"];
let planIndex = new Map();
let currentPlan;

function planOverlaps(plan) {
  if (!plan.execution_date) return [];
  return [...planIndex.values()].filter((other) => other.id !== plan.id
    && other.execution_date === plan.execution_date
    && other.start_time < plan.end_time && plan.start_time < other.end_time).map((other) => other.id);
}

function renderPlanOverlap(ids) {
  const notice = $("plan-overlap");
  notice.hidden = !ids.length;
  notice.replaceChildren();
  if (ids.length) {
    notice.append(el("strong", "시간이 겹치는 계획"));
    const list = el("ul", null, "facts");
    for (const id of ids) {
      const plan = planIndex.get(id);
      const item = el("li");
      item.append(button(plan ? `${plan.title} · ${plan.start_time}–${plan.end_time}` : id,
        () => openSavedPlan(id), "plan-link"));
      list.append(item);
    }
    notice.append(list);
  }
}

function showPlanPost(plan, overlapIds = planOverlaps(plan)) {
  currentPlan = {plan, overlapIds};
  const heading = $("plan-dialog-title");
  heading.textContent = plan.title;
  const timestamp = $("plan-created");
  timestamp.dateTime = plan.created_at;
  timestamp.textContent = `작성 ${when(plan.created_at)}`;
  $("plan-content").replaceChildren(actionList(plan.actions));
  const metadata = $("plan-metadata");
  metadata.replaceChildren();
  const fields = plan.execution_date
    ? [["실행 날짜", plan.execution_date], ["실행 시각", `${plan.start_time}–${plan.end_time}`]]
    : [["실행 일정", "등록된 일정 없음"]];
  if (plan.analysis_id) {
    fields.push(["관련 분석", `${({url: "URL", text: "문자·메신저", screenshot: "이미지"})[plan.target_type] ?? plan.target_type} · ${plan.analysis_id}`]);
  }
  for (const [key, value] of fields) metadata.append(el("dt", key), el("dd", value));
  renderPlanOverlap(overlapIds);
  planForm.hidden = true;
  $("plan-post").hidden = false;
  if (!dialog.open) dialog.showModal();
  heading.focus();
}

function openPlanEditor(value = {}) {
  currentPlan = value;
  const {plan, draft} = value;
  planForm.reset();
  feedback($("plan-feedback"));
  $("plan-dialog-title").textContent = plan ? "예방 글 수정" : "예방 글 쓰기";
  $("save-plan").textContent = plan ? "변경 저장" : "저장";
  $("edit-actions").hidden = Boolean(draft);
  $("plan-schedule").hidden = !plan && !draft;
  $("draft-actions").hidden = !draft;
  $("draft-actions").replaceChildren(...(draft ? [el("h3", "예방 행동 단계"), actionList(draft.actions)] : []));
  if (plan) {
    planForm.elements.title.value = plan.title;
    planForm.elements.actions.value = plan.actions.join("\n");
    for (const field of scheduleFields) planForm.elements[field].value = plan[field] ?? "";
  } else if (value.actions) {
    planForm.elements.actions.value = value.actions.join("\n");
  }
  $("plan-post").hidden = true;
  planForm.hidden = false;
  if (!dialog.open) dialog.showModal();
  $("plan-title").focus();
}
$("new-plan").addEventListener("click", () => openPlanEditor());
$("edit-plan").addEventListener("click", () => openPlanEditor(currentPlan));
$("cancel-plan").addEventListener("click", () => {
  if (currentPlan.plan) showPlanPost(currentPlan.plan, currentPlan.overlapIds);
  else dialog.close();
});
dialog.addEventListener("cancel", (event) => {
  if ($("save-plan").disabled) event.preventDefault();
});

document.querySelectorAll("[data-close]").forEach((control) =>
  control.addEventListener("click", () => $(control.dataset.close).close()));

planForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = $("save-plan");
  if (submit.disabled) return;
  const {plan, draft} = currentPlan;
  submit.disabled = true;
  $("cancel-plan").disabled = true;
  try {
    const input = new FormData(planForm);
    const body = {title: input.get("title").trim()};
    if (!body.title) throw new Error("계획 제목을 입력하세요.");
    if (!draft) {
      body.actions = input.get("actions").split(/\r?\n/).map((entry) => entry.trim()).filter(Boolean);
      if (!body.actions.length || body.actions.length > 20 || body.actions.some((entry) => entry.length > 500)) {
        throw new Error("내용을 1~20줄로 입력하세요. 한 줄은 500자까지 입력할 수 있습니다.");
      }
    } else body.analysis_id = draft.analysis_id;
    if (plan || draft) {
      const schedule = Object.fromEntries(scheduleFields.map((field) => [field, input.get(field)]));
      const values = Object.values(schedule);
      if (plan?.execution_date || values.some(Boolean)) {
        if (!values.every(Boolean)) throw new Error("일정을 지정하려면 날짜와 시작·종료 시각을 모두 입력하세요.");
        Object.assign(body, schedule);
      }
    }
    const saved = await api(plan ? `/api/plans/${encodeURIComponent(plan.id)}` : "/api/plans", plan ? "PATCH" : "POST", body);
    showPlanPost(saved.plan, saved.overlapping_plan_ids);
    feedback($("plans-feedback"), saved.has_overlap ? "저장했습니다. 실행 시간이 겹치는 계획이 있어요."
      : plan ? "변경 사항을 저장했습니다." : "예방 글을 저장했습니다.", saved.has_overlap ? "warn" : "");
    if (location.hash === "#plans") await loadPlans();
    else location.hash = "plans";
  } catch (error) {
    feedback($("plan-feedback"), `저장 실패 · ${error.message}`, "error");
  } finally {
    submit.disabled = false;
    $("cancel-plan").disabled = false;
  }
});

function confirmDelete(description) {
  const modal = $("confirm-dialog");
  $("confirm-text").textContent = description;
  modal.returnValue = "cancel";
  modal.showModal();
  return new Promise((resolve) => modal.addEventListener("close", () => resolve(modal.returnValue === "delete"), {once: true}));
}

function row(title, detail, buttons) {
  const item = el("div", null, "row");
  const copy = el("div");
  copy.append(el("h3", title), el("p", detail, "row-hint"));
  const controls = el("div", null, "row-buttons");
  controls.append(...buttons);
  item.append(copy, controls);
  return item;
}

function scheduleTime(plan, field = "start_time") {
  return plan.execution_date && plan[field] ? Date.parse(`${plan.execution_date}T${plan[field]}`) : NaN;
}

async function openSavedPlan(id, edit = false) {
  const notice = $("plans-feedback");
  try {
    const plan = await api(`/api/plans/${encodeURIComponent(id)}`);
    planIndex.set(id, plan);
    if (edit) openPlanEditor({plan, overlapIds: planOverlaps(plan)});
    else showPlanPost(plan);
  } catch (error) {
    feedback(notice, error.message, "error");
  }
}

async function loadPlans() {
  const list = $("plans-list");
  empty(list, "예방 계획 조회 중");
  try {
    const plans = await api("/api/plans");
    planIndex = new Map(plans.map((plan) => [plan.id, plan]));
    if (dialog.open && currentPlan?.plan && planForm.hidden) {
      renderPlanOverlap(currentPlan.overlapIds ?? []);
    }
    if (!plans.length) { empty(list, "저장한 예방 글 없음", "글쓰기에서 예방 계획을 작성하세요."); return; }
    const recentFirst = [...plans].sort((a, b) => b.created_at.localeCompare(a.created_at));
    list.replaceChildren(...recentFirst.map((plan) => {
      const item = row("", `작성 ${when(plan.created_at)}`, [
        button("상세 보기", () => openSavedPlan(plan.id)),
        button("수정", () => openSavedPlan(plan.id, true)),
        button("삭제", () => deleteItem("plans", plan.id, "선택한 예방 계획을 삭제합니다."), "quiet-delete"),
      ]);
      item.querySelector("h3").append(button(plan.title, () => openSavedPlan(plan.id), "plan-link"));
      return item;
    }));
  } catch (error) {
    if (error.code === "SESSION_REQUIRED") {
      empty(list, "저장한 예방 글 없음", "글쓰기에서 첫 예방 계획을 작성하세요.");
      return;
    }
    empty(list, "예방 계획을 조회할 수 없습니다.", error.message);
  }
}

async function loadHomeActivity() {
  const activity = $("home-activity");
  empty(activity, "최근 활동 불러오는 중");
  const [plans, logs] = await Promise.allSettled([api("/api/plans"), api("/api/logs")]);
  const planData = plans.status === "fulfilled" ? plans.value : [];
  const logData = logs.status === "fulfilled" ? logs.value : [];
  const recentPlan = [...planData].sort((a, b) => b.created_at.localeCompare(a.created_at))[0];
  const now = Date.now();
  const nextPlan = planData.filter((plan) => scheduleTime(plan) >= now).sort((a, b) => scheduleTime(a) - scheduleTime(b))[0];
  const recentLog = [...logData].sort((a, b) => Date.parse(b.started_at) - Date.parse(a.started_at))[0];
  const items = [
    ["최근 저장한 예방 계획", recentPlan?.title, recentPlan && when(recentPlan.created_at), "#plans", "아직 저장한 예방 계획이 없어요.", plans],
    ["가장 가까운 예정 일정", nextPlan?.title, nextPlan && `${nextPlan.execution_date} · ${nextPlan.start_time}–${nextPlan.end_time}`, "#plans", "예정된 일정이 없어요.", plans],
    ["최근 분석 기록", recentLog && when(recentLog.started_at), recentLog && `이벤트 ${recentLog.event_count}개`, recentLog && `#logs/${recentLog.run_id}`, "아직 실행한 분석이 없어요.", logs],
  ];
  activity.replaceChildren(...items.map(([labelText, title, description, href, fallback, response]) => {
    const card = el("article", null, "activity-card");
    card.append(el("h3", labelText));
    if (title) {
      const link = el("a", title);
      link.href = href;
      card.append(link, el("p", description, "row-hint"));
    } else {
      const failed = response.status === "rejected" && response.reason.code !== "SESSION_REQUIRED";
      card.append(el("p", failed ? "활동을 불러오지 못했어요." : fallback, "row-hint"));
    }
    return card;
  }));
}

let activeLogId;

function renderRunOverview(target, events) {
  const phases = [
    ["Planner · 요청 분석 및 작업 계획", (e) => e.event_type === "planner.task" || e.event_type === "node.entered" && ["analyze", "plan"].includes(e.data.node)],
    ["Worker · 검증 작업", (e) => e.event_type === "tool.requested" || e.event_type === "worker.attempt"
      || e.event_type === "llm.decision" && e.data.stage === "message_context"],
    ["Planner · 결과 검토 및 재계획 확인", (e) => e.event_type === "replan.decided" || e.event_type === "node.entered" && ["judge", "replan"].includes(e.data.node)],
    ["로깅 Agent · 실행 검증", (e) => e.event_type === "audit.checked"],
    ["최종 응답 생성", (e) => e.event_type === "response.generated"],
  ];
  const stages = el("ol", null, "run-stages");
  for (const [title, includes] of phases) {
    const entries = events.filter(includes);
    if (!entries.length) continue;
    const stage = el("li");
    stage.append(el("strong", title), el("span", ` #${entries[0].sequence} · ${when(entries[0].occurred_at)}`, "row-hint"));
    stages.append(stage);
  }
  const calls = events.filter((event) => event.event_type === "tool.requested");
  const start = events.find((event) => event.event_type === "run.started");
  const finish = events.find((event) => event.event_type === "run.finished");
  const duration = Date.parse(finish?.occurred_at) - Date.parse(start?.occurred_at);
  const metrics = [`Tool 호출 ${calls.length}회`];
  if (Number.isFinite(duration) && duration >= 0) metrics.push(`전체 소요 ${duration.toLocaleString("ko-KR")} ms`);
  target.append(el("h3", "실행 단계 요약"), el("p", metrics.join(" · "), "row-hint"));
  if (stages.children.length) target.append(stages);
  const outcomes = events.filter((event) => event.event_type === "tool.finished");
  if (outcomes.length) {
    const toolsList = el("ul", null, "facts tool-results");
    for (const event of outcomes) {
      const d = event.data;
      const parts = [toolName(d.tool), d.outcome, Number.isFinite(d.duration_ms) ? `${d.duration_ms} ms` : null];
      toolsList.append(el("li", parts.filter(Boolean).join(" · "), "row-hint"));
    }
    target.append(toolsList);
  }
}

function renderLogEvaluation(target, evaluation) {
  const captions = {normal: "정상", warning: "이상 징후 발견", inconclusive: "판정 불가"};
  const badge = el("strong", captions[evaluation.status] ?? "상태 미확인",
    `result-status ${evaluation.status === "warning" ? "warn" : "neutral"}`);
  target.replaceChildren(badge, el("p", `발견된 경고 ${evaluation.warnings.length}개`, "row-hint"));
  if (!evaluation.complete) {
    target.append(el("p", "일부 검증에 필요한 실행 기록이 충분하지 않아요.", "row-hint"));
    if (evaluation.reason) target.append(el("p", evaluation.reason, "tag"));
  }
  const evidenceRefs = (ids) => ids.map((id) => `#${id.split(":").at(-1)}`).join(", ");
  if (evaluation.warnings.length) {
    const warnings = el("ul", null, "facts");
    for (const warning of evaluation.warnings) {
      const item = el("li", null, "fact");
      item.append(el("strong", label(warning.code)), el("p", warning.reason),
        el("p", `발생 위치 #${warning.location.sequence} · 계획 버전 ${warning.location.revision}`, "row-hint"));
      if (warning.evidence_event_ids.length) item.append(el("p", `근거 이벤트 ${evidenceRefs(warning.evidence_event_ids)}`, "row-hint"));
      warnings.append(item);
    }
    target.append(warnings);
  }
  const diagnosis = evaluation.diagnosis;
  target.append(el("h4", "LLM 원인 진단", "diagnosis-title"));
  if (diagnosis?.status === "completed" && diagnosis.text) {
    target.append(el("p", diagnosis.text));
    if (diagnosis.evidence_event_ids.length) target.append(el("p", `참고 이벤트 ${evidenceRefs(diagnosis.evidence_event_ids)}`, "row-hint"));
    target.append(el("p", "실행 과정의 원인에 대한 참고 정보예요.", "row-hint"));
  } else {
    const states = {pending: "진단 대기 중이에요.", failed: "원인 진단을 완료하지 못했어요."};
    target.append(el("p", states[diagnosis?.status] ?? "저장된 원인 진단이 없어요.", "row-hint"));
    if (diagnosis?.error_code) target.append(el("p", diagnosis.error_code, "tag"));
  }
}

async function loadLog(id) {
  activeLogId = id;
  const detail = $("log-detail");
  empty(detail, "실행 상세 조회 중");
  try {
    const path = `/api/logs/${encodeURIComponent(id)}`;
    const log = await api(path);
    if (activeLogId !== id) return;
    const overview = el("div", null, "log-block");
    renderRunOverview(overview, log.events);
    const evaluation = el("section", null, "log-block evaluation");
    const evaluationBody = el("div");
    evaluation.append(el("h3", "로깅 Agent · 이상 징후 평가"), evaluationBody);
    empty(evaluationBody, "평가를 불러오는 중");
    const timeline = el("div", null, "log-block");
    timeline.append(el("h3", "시간순 실행 기록"));
    const entries = el("div");
    renderTimeline(entries, log.events, true);
    timeline.append(entries);
    detail.replaceChildren(overview, evaluation, timeline);
    try {
      const data = await api(`${path}/evaluation`);
      if (activeLogId === id) renderLogEvaluation(evaluationBody, data);
    } catch (error) {
      if (activeLogId === id) empty(evaluationBody, "평가를 불러오지 못했어요.", error.message);
    }
  } catch (error) {
    if (activeLogId === id) empty(detail, "실행 상세를 조회할 수 없습니다.", error.message);
  }
}

async function loadLogs() {
  const list = $("logs-list");
  empty(list, "실행 로그 조회 중");
  try {
    const logs = await api("/api/logs");
    if (!logs.length) { empty(list, "저장된 실행 로그 없음"); return; }
    list.replaceChildren(...[...logs].sort((a, b) => Date.parse(b.started_at) - Date.parse(a.started_at)).map((log) => row(
      when(log.started_at), `${log.ended_at ? "종료 기록 있음" : "종료 기록 없음"} · 이벤트 ${log.event_count}개 · ${log.run_id}`,
      [
        button("상세", () => {
          const hash = `#logs/${log.run_id}`;
          if (location.hash === hash) loadLog(log.run_id);
          else location.hash = hash;
        }),
        button("삭제", () => deleteItem("logs", log.run_id, "선택한 실행 로그의 모든 이벤트를 삭제합니다."), "quiet-delete"),
      ],
    )));
  } catch (error) {
    if (error.code === "SESSION_REQUIRED") { empty(list, "저장된 실행 로그 없음"); return; }
    empty(list, "실행 로그를 조회할 수 없습니다.", error.message);
  }
}

async function deleteItem(page, id, description) {
  if (!await confirmDelete(description)) return;
  const notice = $(`${page}-feedback`);
  try {
    await api(`/api/${page}/${encodeURIComponent(id)}`, "DELETE");
    feedback(notice, page === "plans" ? "예방 계획을 삭제했습니다." : "실행 로그를 삭제했습니다.");
    if (page === "plans") await loadPlans();
    else {
      if (activeLogId === id) {
        activeLogId = undefined;
        if (location.hash === `#logs/${id}`) history.replaceState(null, "", "#logs");
        empty($("log-detail"), "상세를 보려면 실행을 선택하세요.");
      }
      await loadLogs();
    }
  } catch (error) {
    feedback(notice, `삭제 실패 · ${error.message}`, "error");
  }
}

function navigate() {
  const pages = ["home", "analysis", "plans", "logs"];
  const hash = location.hash.slice(1);
  if (hash === "main") return;
  const analysisRoutes = {analysis: "url", "analysis-url": "url", "analysis-text": "text", call: "call"};
  const analysisType = Object.hasOwn(analysisRoutes, hash) ? analysisRoutes[hash] : null;
  const runId = /^logs\/([0-9a-f]{32})$/.exec(hash)?.[1];
  const page = analysisType ? "analysis" : runId ? "logs" : pages.includes(hash) ? hash : "home";
  for (const key of pages) $(`${key}-page`).hidden = key !== page;
  for (const link of document.querySelectorAll(".site-header nav a")) {
    if (link.hash === `#${page}`) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  if (analysisType) {
    const navigation = $("analysis-nav");
    const call = analysisType === "call";
    for (const link of navigation.querySelectorAll("a")) {
      if (analysisRoutes[link.hash.slice(1)] === analysisType) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    $("message-view").hidden = call;
    $("call-view").hidden = !call;
    if (!call) selectAnalysisInput(analysisType);
    if (!navigation.contains(document.activeElement) && hash !== "analysis") {
      if (call) $("call-channel").focus();
      else message.focus();
    }
  }
  if (page === "home") loadHomeActivity();
  if (page === "plans") loadPlans();
  if (page === "logs") {
    if (runId) loadLog(runId);
    else if (!activeLogId) empty($("log-detail"), "상세를 보려면 실행을 선택하세요.");
    loadLogs();
  }
}
window.addEventListener("hashchange", navigate);
navigate();
