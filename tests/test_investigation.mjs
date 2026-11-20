import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {test} from "node:test";

const moduleSource = await readFile(new URL("../frontend/investigation.js", import.meta.url));
const {buildInvestigation} = await import(`data:text/javascript;base64,${moduleSource.toString("base64")}`);
const labels = {
  statuses: {SUSPICIOUS: ["주의", "warn"], NO_KNOWN_MATCH: ["일치 없음", "unmatched"],
    INSUFFICIENT_EVIDENCE: ["근거 부족", "neutral"]},
  scopes: {exact_url: "입력 URL"}, toolName: (x) => x, label: (x) => x, when: (x) => x,
};
const run = "r";
const ev = (sequence, event_type, data = {}, run_id = run) => ({sequence, event_type, data, run_id});
const response = (overrides = {}) => ({
  run_id: run,
  analysis: {
    status: "SUSPICIOUS", tool_outcomes: {}, tool_errors: {}, evidence: [], local_signals: [], actions: ["공식 경로 확인"],
    ...overrides,
  },
});

test("phone keeps selected call facts and prevention actions without inventing URL lookups", () => {
  const model = buildInvestigation(response({local_signals: ["인증번호 요구"], actions: []}), "call",
    [ev(1, "run.started"), ev(5, "response.generated")],
    {...labels, callFacts: [["연락 방식", "영상통화"]], callActions: ["공식 번호 확인"]});
  assert.equal(model.mode, "전화·영상통화");
  assert.deepEqual(model.nodes[0].facts.at(-1), ["연락 방식", "영상통화"]);
  assert.deepEqual(model.nodes.find((node) => node.id === "actions").facts, [["권장 행동", "공식 번호 확인"]]);
  assert.ok(!model.nodes.some((node) => node.kind === "lookup"));
  assert.deepEqual(model.nodes.find((node) => node.id === "verdict").seqs, [5]);
});

test("matches an observation to an exact unique tool outcome and keeps event order", () => {
  const result = response({
    tool_outcomes: {google_safe_browsing: "NO_MATCH", virustotal_url: "REPORT"},
    tool_errors: {urlscan_history: "TIMEOUT"},
    provider_comparison: "different",
    evidence: [
      {tool: "google_safe_browsing", outcome: "NO_MATCH", eligible: true, observed_at: null, scope: "exact_url", scope_met: true},
      {tool: "virustotal_url", outcome: "REPORT", eligible: false, engine_counts: {malicious: 2, harmless: 0}},
    ],
  });
  const model = buildInvestigation(result, "url", [
    ev(12, "response.generated"), ev(5, "tool.finished", {tool: "google_safe_browsing", outcome: "NO_MATCH"}),
    ev(2, "planner.task", {tool: "virustotal_url"}), ev(9, "tool.finished", {tool: "virustotal_url", outcome: "REPORT"}),
    ev(10, "replan.decided", {performed: true}), ev(3, "tool.requested", {tool: "google_safe_browsing"}),
    ev(6, "tool.requested", {tool: "virustotal_url"}), ev(99, "tool.requested", {tool: "foreign"}, "other-run"),
  ], labels);
  assert.deepEqual(model.timeline.map((event) => event.sequence), [2, 3, 5, 6, 9, 10, 12]);
  assert.deepEqual(model.nodes.find((node) => node.id === "evidence-0").seqs, [5]);
  assert.deepEqual(model.nodes.find((node) => node.id === "evidence-1").seqs, [9]);
  assert.equal(model.nodes.find((node) => node.id === "tool-urlscan_history").tone, "error");
  assert.equal(model.nodes.find((node) => node.id === "tool-google_safe_browsing").tone, "neutral");
  assert.ok(model.edges.some((edge) => edge.from === "evidence-0" && edge.to === "verdict" && edge.inferred));
  assert.ok(!model.edges.some((edge) => edge.from === "evidence-1" && edge.to === "verdict"));
});

test("text-only and missing logs do not invent lookups, repeats, or any extracted URL", () => {
  const result = response({
    local_signals: ["인증번호 요구 표현"],
    text_assessment: {url_lookup: "not_attempted", context: {signals: [{label: "신원 확인 필요", quote: "private raw quote"}]}},
  });
  const model = buildInvestigation(result, "text", null, labels);
  assert.deepEqual(model.nodes.map((node) => node.id), ["input", "signal-0", "signal-1", "verdict", "actions"]);
  assert.deepEqual(model.timeline, []);
  assert.ok(!JSON.stringify(model).includes("private raw quote"));
  assert.equal(model.nodes.find((node) => node.id === "verdict").at, Infinity);
});

test("planned-only tools and ambiguous retries do not imply a unique evidence event", () => {
  const model = buildInvestigation(response({
    tool_outcomes: {urlscan_history: "NO_CANDIDATES"},
    evidence: [{tool: "urlscan_history", outcome: "NO_CANDIDATES", eligible: false}],
  }), "url", [
    ev(1, "planner.task", {tool: "virustotal_url"}),
    ev(2, "tool.finished", {tool: "urlscan_history", outcome: "NO_CANDIDATES"}),
    ev(3, "tool.finished", {tool: "urlscan_history", outcome: "NO_CANDIDATES"}),
  ], labels);
  assert.ok(!model.nodes.some((node) => node.id === "tool-virustotal_url"));
  assert.deepEqual(model.nodes.find((node) => node.id === "evidence-0").seqs, []);
  assert.equal(model.nodes.find((node) => node.id === "tool-urlscan_history").tone, "empty");
  assert.ok(!model.timeline.some((event) => event.event_type === "replan.decided"));
});
