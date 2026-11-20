const svgNamespace = "http://www.w3.org/2000/svg";
const completedOutcomes = new Set(["MATCH", "NO_MATCH", "REPORT", "NO_RECORD", "CANDIDATES", "NO_CANDIDATES"]);
const categories = {all: "전체", signal: "위험 정황", lookup: "보안 조회", verdict: "AI 판단", action: "예방 행동"};
const eligibleEvents = new Set([
  "run.started", "node.entered", "node.finished", "planner.task", "worker.attempt", "worker.decision",
  "tool.requested", "tool.finished", "llm.decision", "message_context.finished", "audit.checked",
  "replan.decided", "response.generated", "error.handled", "run.finished",
]);

function el(tag, title, className) {
  const node = document.createElement(tag);
  if (title) node.textContent = title;
  if (className) node.className = className;
  return node;
}

function control(title, handler) {
  const button = el("button", title);
  button.type = "button";
  button.addEventListener("click", handler);
  return button;
}

function safe(value) {
  return String(value).replace(/(?:[a-z][a-z\d+.-]*:\/\/|www\.)\S+|[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi, "[가림]")
    .replace(/(?:비밀번호|인증번호|token|password|api[_ -]?key)\s*[:=]\s*[^\s,;]+|\b(?:sk-|Bearer\s+)[a-z\d_-]+|(?<!\d)\d(?:[ -]?\d){5,}(?!\d)/gi, "[가림]");
}

function outcomeTone(outcome) {
  if (outcome === "MATCH") return "warn";
  if (outcome === "NO_MATCH") return "neutral";
  if (outcome === "NO_RECORD" || outcome === "NO_CANDIDATES") return "empty";
  return completedOutcomes.has(outcome) ? "observed" : "error";
}

export function buildInvestigation(result, target, events, labels) {
  const analysis = result.analysis;
  const timeline = (events ?? []).filter((event) => eligibleEvents.has(event.event_type)
    && Number.isInteger(event.sequence) && (!event.run_id || event.run_id === result.run_id))
    .sort((a, b) => a.sequence - b.sequence);
  const firstEvent = (predicate) => timeline.find(predicate)?.sequence ?? Infinity;
  const isNode = (event, node) => event.data.node === node;
  const verdictEvents = timeline.filter((event) => ["replan.decided", "audit.checked", "response.generated"].includes(event.event_type)
    || ["judge", "replan", "respond"].includes(event.data.node));
  const responseAt = firstEvent((e) => e.event_type === "response.generated");
  const nodes = [];
  const edges = [];
  const connect = (from, to, inferred = false) => edges.push({from, to, inferred});
  const add = (node) => nodes.push(node);
  const byTool = new Map();
  const toolNames = new Set([
    ...Object.keys(analysis.tool_outcomes), ...Object.keys(analysis.tool_errors),
    ...analysis.evidence.map((item) => item.tool),
    ...timeline.filter((e) => ["tool.requested", "tool.finished"].includes(e.event_type)).map((e) => e.data.tool),
  ].filter(Boolean));
  const mode = {text: "문자·메신저", call: "전화·영상통화", url: "URL"}[target];
  const inputSummary = {text: "문자 표현과 포함된 링크 검토", call: "선택한 통화 상황과 입력한 설명 검토",
    url: "입력한 링크와 조회 조건 검토"}[target];
  const inputFacts = [["입력 유형", mode], ["입력 요약", inputSummary], ...(labels.callFacts ?? [])];
  const actions = labels.callActions ?? analysis.actions;
  const context = analysis.text_assessment?.context ?? analysis.message_context;
  const signals = [...new Set([...analysis.local_signals, ...(context?.signals ?? []).map((item) => item.label)])];
  const [verdict, tone] = labels.statuses[analysis.status] ?? labels.statuses.INSUFFICIENT_EVIDENCE;
  add({id: "input", kind: "input", column: 1, title: "분석 대상", subtitle: mode,
    at: -Infinity, seqs: timeline.filter((e) => e.event_type === "run.started" || isNode(e, "analyze")).map((e) => e.sequence),
    facts: inputFacts});
  signals.forEach((signal, index) => {
    const id = `signal-${index}`;
    const local = analysis.local_signals.includes(signal);
    const related = local ? timeline.filter((e) => e.event_type === "node.finished" && isNode(e, "analyze"))
      : timeline.filter((e) => e.event_type === "message_context.finished" && ["analyzed", "cache_hit"].includes(e.data.status));
    add({id, kind: "signal", column: 1, title: signal, subtitle: local ? "입력 표현" : "문맥 분석",
      at: related[0]?.sequence ?? Infinity, seqs: related.map((e) => e.sequence),
      facts: [["정황 출처", local ? "입력 표현의 규칙 분석" : "문맥 분석 결과"]]});
    connect("input", id, !local);
  });
  for (const tool of toolNames) {
    const id = `tool-${tool}`;
    const used = timeline.filter((e) => e.data.tool === tool
      && ["planner.task", "worker.attempt", "tool.requested", "tool.finished", "worker.decision"].includes(e.event_type));
    const requests = used.filter((e) => e.event_type === "tool.requested");
    const outcomes = used.filter((e) => e.event_type === "tool.finished");
    const observed = analysis.tool_outcomes[tool] ?? outcomes.at(-1)?.data.outcome;
    const error = analysis.tool_errors[tool];
    const status = error ?? observed;
    byTool.set(tool, {id, outcomes});
    add({id, kind: "lookup", column: 2, title: labels.toolName(tool),
      subtitle: status ? labels.label(status) : "결과 기록 없음", tone: status ? outcomeTone(status) : "neutral",
      at: requests[0]?.sequence ?? outcomes[0]?.sequence ?? Infinity, seqs: used.map((event) => event.sequence),
      facts: [["출처", labels.toolName(tool)], ["조회 결과", status ? labels.label(status) : "확인되지 않음"],
        ...(observed && error && observed !== error ? [["공급자 응답", labels.label(observed)]] : []),
        ...(requests.length ? [["기록된 호출", `${requests.length}회`]] : [])]});
    connect("input", id);
  }
  analysis.evidence.forEach((item, index) => {
    const id = `evidence-${index}`;
    const tool = byTool.get(item.tool);
    // An outcome can be repeated. Only bind a provider observation to a unique matching tool result.
    const matching = tool?.outcomes.filter((e) => e.data.outcome === item.outcome) ?? [];
    const bound = matching.length === 1 && analysis.evidence.filter((e) => e.tool === item.tool && e.outcome === item.outcome).length === 1
      ? matching[0] : null;
    const facts = [
      ["출처", item.source ?? labels.toolName(item.tool)],
      ["조회 범위", item.scope ? labels.scopes[item.scope] ?? item.scope : "확인되지 않음"],
      ["결과 코드", item.outcome ?? "확인되지 않음"],
      ["관측 시각", item.observed_at ? labels.when(item.observed_at) : "확인되지 않음"],
      ["범위 충족", item.scope_met], ["신선도 충족", item.freshness_met], ["판단 근거 사용 가능", item.eligible],
      ["탐지 신호", item.signal], ["보고 엔진 수", item.reported_engines],
      ...Object.entries(item.engine_counts ?? {}).map(([key, value]) => [`엔진 · ${key}`, value]),
      ...(item.exclusion_reasons ?? []).map((reason) => ["제외 사유", reason.message]),
    ].filter(([, value]) => value != null);
    add({id, kind: "lookup", visual: "evidence", column: 3, title: `근거 · ${item.source ?? labels.toolName(item.tool)}`,
      subtitle: labels.label(item.outcome), tone: outcomeTone(item.outcome), seqs: bound ? [bound.sequence] : [],
      at: bound?.sequence ?? Infinity, facts});
    if (tool) connect(tool.id, id);
    if (item.eligible) connect(id, "verdict", true);
  });
  add({id: "verdict", kind: "verdict", column: 4, title: "종합 판단", subtitle: verdict, tone,
    seqs: verdictEvents.map((e) => e.sequence), at: responseAt,
    facts: [["판단 근거", labels.verdictNote ?? analysis.message],
      ...(analysis.provider_comparison ? [["공급자 비교", {
        different: "공급자별 결과가 달라요. 각 근거의 조회 범위와 관측 시각을 확인하세요.",
        agreement: "두 공급자에서 입력 URL의 위험 신호를 확인했어요.",
        scope_differs: "공급자마다 조회 범위가 달라요.",
      }[analysis.provider_comparison]]] : []),
      ...(analysis.conditions?.max_age_hours != null ? [["요청 기간", `최근 ${analysis.conditions.max_age_hours}시간`],
        ["기간 조건 충족", analysis.constraints_met]] : []),
      ...(analysis.conditions?.exact_only ? [["요청 범위", "입력 URL과 정확히 일치하는 기록"]] : []),
      ...(analysis.minimum_observed_at && analysis.conditions?.max_age_hours != null
        ? [["관측 기준 시각", labels.when(analysis.minimum_observed_at)]] : []),
      ...(analysis.text_assessment?.url_lookup === "not_attempted" ? [["외부 링크 조회", "수행하지 않음"]] : []),
      ...(analysis.llm_error ? [["AI 분석 제한", labels.label(analysis.llm_error)]] : []),
      ...(analysis.stop_reason ? [["종료 사유", labels.label(analysis.stop_reason)]] : []),
      ...(analysis.replans > 0 ? [["재계획", `${analysis.replans}회`]] : []),
    ].filter(([, value]) => value != null)});
  if (!analysis.evidence.some((item) => item.eligible)) connect("input", "verdict", true);
  if (actions.length) {
    add({id: "actions", kind: "action", column: 4, title: "예방 행동", subtitle: `${actions.length}개 권장 행동`,
      seqs: Number.isFinite(responseAt) ? [responseAt] : [], at: responseAt,
      facts: actions.map((action) => ["권장 행동", action])});
    connect("verdict", "actions");
  }
  return {nodes, edges, timeline, mode, signals, verdict, tone, actions};
}

export function mountInvestigation(root, result, target, labels) {
  let model = buildInvestigation(result, target, null, labels);
  let filter = "all", focus = "verdict", activeEvent = null, linked = [], zoom = 1, speed = 1;
  let playhead = null, timer = 0, disposed = false;
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const header = el("header", null, "investigation-header");
  header.append(el("h2", "AI 위험 조사 · 분석 근거와 Agent 실행 흐름"));
  const banner = el("div", null, "investigation-banner");
  const verdict = el("strong", model.verdict, `investigation-verdict ${model.tone}`);
  const summary = el("div", null, "investigation-summary");
  const id = el("p", `분석 ID · ${result.run_id}`, "investigation-id");
  id.title = "이 분석과 연결된 실행 기록을 식별하는 번호";
  summary.append(verdict, el("p", target === "call" ? "통화 정황을 바탕으로 확인한 결과입니다."
    : "위험 목록에 없더라도 안전이 확인된 것은 아니에요."), id);
  if (result.status === "partial") summary.append(el("p", "일부 조회를 완료하지 못했어요."));
  banner.append(summary);
  if (result.plan_draft) banner.append(control("예방 계획 저장", () => labels.save(result.plan_draft)));
  else if (labels.saveActions) banner.append(control("예방 계획 저장", labels.saveActions));
  if (model.actions.length) {
    const advice = el("div", null, "investigation-advice");
    const mascot = el("img");
    mascot.src = "/assets/shieldy-transparent.png";
    mascot.alt = "";
    mascot.width = 42;
    mascot.height = 53;
    const note = el("div");
    note.append(el("strong", "쉴디의 예방 안내"), el("p", safe(model.actions[0])));
    advice.append(mascot, note);
    banner.append(advice);
  }

  const layout = el("div", null, "investigation-layout");
  const overview = el("section", null, "investigation-card investigation-overview");
  overview.append(el("h3", "분석 개요"), el("p", model.mode), el("p", "입력 원문과 링크는 가렸어요."));
  overview.append(el("h4", "핵심 정황"));
  if (model.signals.length) {
    const list = el("ul");
    model.signals.forEach((signal) => list.append(el("li", safe(signal))));
    overview.append(list);
  } else overview.append(el("p", "표시할 정황 없음"));

  const network = el("section", null, "investigation-card investigation-network");
  const toolbar = el("div", null, "investigation-toolbar");
  const filterSelect = el("select");
  filterSelect.setAttribute("aria-label", "그래프 범주");
  for (const [value, title] of Object.entries(categories)) {
    const option = el("option", title);
    option.value = value;
    filterSelect.append(option);
  }
  filterSelect.addEventListener("change", () => {
    filter = filterSelect.value;
    if (!model.nodes.some((node) => node.id === focus && visible(node))) focus = "input";
    renderGraph();
    renderDetails();
  });
  toolbar.append(filterSelect, control("확대", () => setZoom(zoom + .2)),
    control("축소", () => setZoom(zoom - .2)), control("화면 맞춤", () => setZoom(1)));
  const viewport = el("div", null, "investigation-viewport");
  viewport.tabIndex = 0;
  viewport.setAttribute("role", "region");
  viewport.setAttribute("aria-label", "위협 추적 네트워크 그래프");
  const graph = el("div", null, "investigation-graph");
  const lines = document.createElementNS(svgNamespace, "svg");
  lines.setAttribute("aria-hidden", "true");
  graph.append(lines);
  viewport.append(graph);
  network.append(el("h3", "위협 추적 네트워크"), toolbar, viewport,
    el("p", "실선 · 기록으로 연결된 항목   /   점선 · 판단에 참고할 수 있는 항목", "investigation-legend"));

  const details = el("section", null, "investigation-card investigation-details");
  details.setAttribute("aria-live", "polite");
  layout.append(overview, network, details);
  const playback = el("section", null, "investigation-card investigation-playback");
  const playbackControls = el("div", null, "investigation-toolbar");
  const play = control("재생", () => timer ? pause() : startPlaying());
  const reset = control("처음으로", () => {
    pause();
    seek(0);
  });
  const all = control("전체 보기", () => { pause(); seek(null); });
  const rate = el("select");
  rate.setAttribute("aria-label", "재생 속도");
  for (const value of [.5, 1, 2]) {
    const option = el("option", `${value}×`);
    option.value = value;
    option.selected = value === 1;
    rate.append(option);
  }
  rate.addEventListener("change", () => {
    speed = Number(rate.value);
    if (timer) { pause(); startPlaying(); }
  });
  const scrub = el("input");
  scrub.type = "range";
  scrub.min = 0;
  scrub.step = 1;
  scrub.setAttribute("aria-label", "저장된 로그 재생 위치");
  scrub.addEventListener("input", () => {
    pause();
    seek(Number(scrub.value));
  });
  playbackControls.append(play, reset, all, rate, scrub);
  const notice = el("p", "실행 로그를 불러오는 중이에요.", "investigation-note");
  const records = el("ol", null, "investigation-events");
  playback.append(el("h3", "AI 수사 타임라인"), el("p", "저장된 로그 재생"), playbackControls, notice, records);
  root.replaceChildren(header, banner, layout, playback);
  root.hidden = false;

  const graphButtons = new Map();
  const eventButtons = new Map();
  function visible(node) {
    const category = filter === "all" || node.kind === filter || node.kind === "input" || node.kind === "verdict";
    return category && (playhead === null || node.at <= (model.timeline[playhead - 1]?.sequence ?? -Infinity)
      || playhead === model.timeline.length);
  }

  function linesForVisibleNodes() {
    const rect = graph.getBoundingClientRect();
    lines.replaceChildren();
    if (!rect.width || !rect.height) return;
    lines.setAttribute("viewBox", `0 0 ${rect.width} ${rect.height}`);
    for (const edge of model.edges) {
      const from = graphButtons.get(edge.from)?.getBoundingClientRect();
      const to = graphButtons.get(edge.to)?.getBoundingClientRect();
      if (!from || !to) continue;
      const vertical = Math.abs(from.left - to.left) < 5;
      const x1 = (vertical ? from.left + from.width / 2 : from.right) - rect.left;
      const x2 = (vertical ? to.left + to.width / 2 : to.left) - rect.left;
      const y1 = (vertical ? from.bottom : from.top + from.height / 2) - rect.top;
      const y2 = (vertical ? to.top : to.top + to.height / 2) - rect.top;
      const mid = (x1 + x2) / 2, middleY = (y1 + y2) / 2;
      const path = document.createElementNS(svgNamespace, "path");
      path.setAttribute("d", vertical ? `M ${x1} ${y1} C ${x1} ${middleY} ${x2} ${middleY} ${x2} ${y2}`
        : `M ${x1} ${y1} C ${mid} ${y1} ${mid} ${y2} ${x2} ${y2}`);
      const selected = focus === edge.from || focus === edge.to || linked.includes(edge.from) || linked.includes(edge.to);
      path.setAttribute("class", `${edge.inferred ? "inferred" : ""} ${selected ? "linked" : ""}`);
      lines.append(path);
    }
  }

  function setZoom(value) {
    zoom = Math.max(.8, Math.min(1.8, value));
    graph.style.zoom = String(zoom);
    if (zoom === 1) {
      graph.style.width = "";
      viewport.scrollTo(0, 0);
    } else {
      fitZoomWidth();
    }
    linesForVisibleNodes();
  }

  function fitZoomWidth() {
    const width = viewport.clientWidth;
    if (width && graph.style.width !== `${width}px`) graph.style.width = `${width}px`;
  }

  function renderGraph() {
    const previous = new Set(graphButtons.keys());
    graphButtons.clear();
    const columns = Array.from({length: 4}, () => el("div", null, "investigation-column"));
    for (const node of model.nodes.filter(visible)) {
      const choice = control(safe(node.title), () => {
        focus = node.id;
        activeEvent = null;
        linked = [];
        updateSelection();
        renderDetails();
      });
      choice.className = `investigation-node kind-${node.visual ?? node.kind} ${node.tone ?? ""}`;
      const icon = el("span", {input: "◎", signal: "◇", lookup: "⌕", evidence: "▤", verdict: "!", action: "✓"}[node.visual ?? node.kind],
        "investigation-node-icon");
      icon.setAttribute("aria-hidden", "true");
      choice.prepend(icon);
      if (playhead !== null && !previous.has(node.id)) choice.classList.add("is-revealed");
      choice.append(el("small", safe(node.subtitle)));
      graphButtons.set(node.id, choice);
      columns[node.column - 1].append(choice);
    }
    graph.replaceChildren(lines, ...columns);
    updateSelection();
  }

  function updateSelection() {
    const node = model.nodes.find((item) => item.id === focus);
    for (const [key, button] of graphButtons) {
      button.setAttribute("aria-pressed", String(key === focus));
      button.classList.toggle("is-linked", linked.includes(key));
    }
    for (const [sequence, button] of eventButtons) {
      const selected = sequence === activeEvent;
      button.setAttribute("aria-pressed", String(selected));
      button.classList.toggle("is-linked", selected || (activeEvent === null && Boolean(node?.seqs.includes(sequence))));
    }
    linesForVisibleNodes();
  }

  function renderDetails() {
    const selected = model.nodes.find((node) => node.id === focus && visible(node));
    const event = model.timeline.find((item) => item.sequence === activeEvent);
    details.replaceChildren(el("h3", "근거 상세"));
    const rows = el("dl");
    if (selected) {
      details.append(el("h4", safe(selected.title)), el("p", safe(selected.subtitle)));
      for (const [key, value] of selected.facts) {
        rows.append(el("dt", key), el("dd", typeof value === "boolean" ? value ? "충족" : "미충족"
          : typeof value === "number" ? String(value) : safe(value)));
      }
      if (selected.seqs.length) rows.append(el("dt", "관련 로그 순번"), el("dd", selected.seqs.map((seq) => `#${seq}`).join(", ")));
    }
    if (event) {
      const [title, description] = labels.describeEvent(event);
      rows.append(el("dt", `선택 로그 #${event.sequence}`), el("dd", safe(title)),
        el("dt", "발생 시각"), el("dd", labels.when(event.occurred_at)));
      if (description) rows.append(el("dt", "기록"), el("dd", safe(description)));
    }
    if (!rows.children.length) details.append(el("p", "노드를 선택하면 근거를 볼 수 있어요."));
    else details.append(rows);
  }

  function selectEvent(event, reveal = false) {
    activeEvent = event.sequence;
    const matches = model.nodes.filter((node) => node.seqs.includes(event.sequence));
    linked = matches.map((node) => node.id);
    const primary = matches.find((node) => node.id.startsWith("evidence-")) ?? matches[0];
    focus = primary?.id ?? null;
    if (primary && !visible(primary) && filter !== "all") {
      filter = "all";
      filterSelect.value = filter;
    }
    renderGraph();
    renderDetails();
    if (reveal && primary) {
      const node = graphButtons.get(primary.id)?.getBoundingClientRect();
      const frame = viewport.getBoundingClientRect();
      if (node && (node.left < frame.left || node.right > frame.right || node.top < frame.top || node.bottom > frame.bottom)) {
        viewport.scrollBy({left: node.left - frame.left, top: node.top - frame.top});
      }
    }
  }

  function renderTimeline() {
    eventButtons.clear();
    records.replaceChildren(...model.timeline.map((event) => {
      const [title, description] = labels.describeEvent(event);
      const row = el("li");
      const card = control(null, () => {
        pause();
        playhead = null;
        scrub.value = model.timeline.length;
        for (const row of records.children) row.classList.remove("is-upcoming");
        selectEvent(event, true);
      });
      const d = event.data;
      const status = d.ok === false || d.status === "failed" || event.event_type === "error.handled" ? "실패·제한"
        : d.ok === true || ["completed", "verified", "analyzed"].includes(d.status) ? "완료" : d.status;
      card.append(el("span", `#${event.sequence} · ${labels.when(event.occurred_at)}`, "investigation-event-meta"),
        el("strong", safe(title)));
      if (status) card.append(el("small", safe(status)));
      if (description) card.append(el("span", safe(description), "investigation-event-meta"));
      eventButtons.set(event.sequence, card);
      row.append(card);
      return row;
    }));
    for (const control of playbackControls.children) control.disabled = !model.timeline.length;
    scrub.max = model.timeline.length;
    scrub.value = playhead ?? model.timeline.length;
    updateSelection();
  }

  function seek(value) {
    playhead = value;
    scrub.value = value ?? model.timeline.length;
    const event = value === null ? null : model.timeline[value - 1];
    for (const [index, row] of [...records.children].entries()) {
      row.classList.toggle("is-upcoming", value !== null && index >= value);
    }
    if (event) {
      selectEvent(event);
      notice.textContent = `재생 위치 ${value} / ${model.timeline.length} · 로그 #${event.sequence}`;
      eventButtons.get(event.sequence)?.scrollIntoView({block: "nearest", inline: "nearest", behavior: "instant", container: "nearest"});
    } else {
      focus = value === null ? "verdict" : "input";
      linked = [];
      activeEvent = null;
      renderGraph();
      renderDetails();
      notice.textContent = value === null ? `실행 이벤트 ${model.timeline.length}개` : "재생을 처음으로 돌렸어요.";
    }
  }

  function pause() {
    window.clearInterval(timer);
    timer = 0;
    play.textContent = "재생";
  }

  function startPlaying() {
    if (playhead === null || playhead >= model.timeline.length) seek(0);
    play.textContent = "일시정지";
    timer = window.setInterval(() => {
      seek(playhead + 1);
      if (playhead >= model.timeline.length) pause();
    }, (reducedMotion.matches ? 950 : 700) / speed);
  }

  const observer = new ResizeObserver(() => {
    if (zoom !== 1) fitZoomWidth();
    linesForVisibleNodes();
  });
  observer.observe(graph);
  observer.observe(viewport);
  renderGraph();
  renderDetails();
  renderTimeline();
  return {
    update(events, failure) {
      if (disposed) return;
      model = buildInvestigation(result, target, events, labels);
      notice.textContent = failure ? `${failure} · 분석 응답으로 확인한 일부 정보만 표시합니다.`
        : model.timeline.length ? `실행 이벤트 ${model.timeline.length}개` : "표시할 실행 로그가 없어요.";
      renderGraph();
      renderTimeline();
      renderDetails();
    },
    dispose() {
      disposed = true;
      pause();
      observer.disconnect();
      root.hidden = true;
      root.replaceChildren();
    },
  };
}
