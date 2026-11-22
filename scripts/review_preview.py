"""Render a standalone local review page from strictly bounded metadata."""

import base64
import hashlib
import json
import re

from review_policy import LABELS, ORDINARY_TYPES


TYPE_LABELS = {
    "SECRET": "凭据", "CNID": "身份证号", "SSN": "社会保障号码", "CARD": "支付卡号",
    "ACCOUNT": "账号", "PHONE": "电话", "EMAIL": "邮箱", "IP": "IP 地址", "URL": "链接",
    "SENSITIVE": "敏感值", "PERSON": "人名", "ORG": "组织", "LOCATION": "地址",
    "PROJECT": "项目",
}
DOUBT_TYPES = frozenset(LABELS.values())
CHANGE_KEYS = frozenset({"line", "column", "start", "end", "kind", "marker"})
DOUBT_KEYS = frozenset({"line", "column", "start", "end", "kind", "reason"})
MAX_FILE_BYTES = 4 * 1024 * 1024

STYLE = """
:root { color-scheme: light; font: 16px/1.55 system-ui, sans-serif; color: #192521; background: #f3f6f3;
  --panel: #fff; --line: #dce5df; --muted: #56665f; --accent: #196248; --tint: #ebf3ee; --warn: #7c4a16; }
* { box-sizing: border-box }
[hidden] { display: none !important }
body { margin: 0 }
main { max-width: 69rem; margin: auto; padding: clamp(1rem, 4vw, 3rem) }
h1 { margin: 0; font-size: clamp(1.8rem, 3.5vw, 2.6rem); line-height: 1.2; letter-spacing: -.025em }
h2 { margin: 0; font-size: 1.1rem }
p { margin: .5rem 0 }
.summary, .muted { color: var(--muted) }
.summary { margin: .65rem 0 1.4rem }
.filters { display: flex; align-items: center; flex-wrap: wrap; gap: .6rem; margin-bottom: 1.2rem }
input, select, button { font: inherit; color: inherit }
select, button { border: 1px solid var(--line); border-radius: .4rem; padding: .35rem .6rem; background: var(--panel) }
button { cursor: pointer }
button:hover:not(:disabled) { border-color: var(--accent); background: var(--tint) }
button:disabled { cursor: default; opacity: .55 }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px }
.grid { display: grid; grid-template-columns: minmax(0, 1.45fr) minmax(17rem, 1fr); gap: 1.2rem; align-items: start }
section, aside { background: var(--panel); border: 1px solid var(--line); border-radius: .8rem; padding: 1rem 1.1rem }
section + section { margin-top: 1.2rem }
aside { position: sticky; top: 1rem }
ol { padding: 0; list-style: none; margin: .6rem 0 }
li { display: flex; gap: .75rem; justify-content: space-between; align-items: center; padding: .6rem 0;
  border-top: 1px solid var(--line); overflow-wrap: anywhere }
li button { flex: 0 0 auto }
small { color: var(--muted); font-size: .83rem }
code, pre { font-family: ui-monospace, monospace }
pre { padding: .75rem; border-radius: .5rem; background: var(--tint); white-space: pre-wrap; overflow-wrap: anywhere }
#doubts h2 { color: var(--warn) }
#context-title { font-weight: 650 }
input[type=file] { width: 100%; margin: .6rem 0 .2rem }
@media (max-width: 46rem) { .grid { grid-template-columns: 1fr } aside { position: static; grid-row: 1 } }
@media (prefers-color-scheme: dark) {
  :root { color-scheme: dark; color: #e6ede8; background: #16201c; --panel: #202c27;
    --line: #42564b; --muted: #b0c2b7; --accent: #96d5b7; --tint: #31453a; --warn: #edbc86; }
}
"""

SCRIPT = """
"use strict";
const data = JSON.parse(document.getElementById("review-data").textContent);
const PAGE = 40;
const controls = document.getElementById("filter");
const file = document.getElementById("candidate");
const status = document.getElementById("candidate-status");
const title = document.getElementById("context-title");
const context = document.getElementById("context");
const reveal = document.getElementById("reveal");
const counts = { doubts: PAGE, changes: PAGE };
let points = null;
let focused = null;
let generation = 0;
let showingValue = false;

function category(kind) {
  return data.ordinary.includes(kind) ? "普通敏感" : "高敏";
}

function entryLocation(row, group) {
  return (group === "changes" ? "原文" : "候选") + "第 " + row.line + " 行，第 " + row.column + " 列";
}

function matches(row) {
  return controls.value === "all" ||
    (controls.value === "ordinary" && data.ordinary.includes(row.kind)) ||
    (controls.value === "high" && !data.ordinary.includes(row.kind)) ||
    controls.value === row.kind;
}

function item(row, group) {
  const entry = document.createElement("li");
  const details = document.createElement("div");
  const where = document.createElement("small");
  where.textContent = entryLocation(row, group) + " · " + category(row.kind);
  const label = document.createElement("div");
  label.textContent = data.labels[row.kind];
  if (group === "doubts") {
    label.append(document.createTextNode("标注后仍有未遮盖内容"));
  } else {
    const marker = document.createElement("code");
    marker.textContent = row.marker;
    label.append(document.createTextNode(" → "), marker);
  }
  details.append(where, label);
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "查看此处";
  button.disabled = !points;
  button.setAttribute("aria-label", "查看" + entryLocation(row, group));
  button.addEventListener("click", () => {
    focused = { row, group };
    showContext(false);
    title.focus();
  });
  entry.append(details, button);
  return entry;
}

function render(group) {
  const rows = data[group].filter(matches);
  const list = document.getElementById(group + "-rows");
  const more = document.getElementById(group + "-more");
  document.getElementById(group + "-shown").textContent = rows.length ? "显示 " + Math.min(rows.length, counts[group]) + " / " + rows.length + " 项" :
    (data[group].length ? "此筛选下没有条目" : group === "doubts" ? "未发现当前规则定义的疑点" : "没有替换项");
  list.replaceChildren(...rows.slice(0, counts[group]).map(row => item(row, group)));
  more.hidden = rows.length <= counts[group];
}

function renderLists() {
  render("doubts");
  render("changes");
}

function showContext(showValue) {
  showingValue = showValue;
  context.hidden = !focused;
  reveal.hidden = !focused || focused.group !== "doubts";
  reveal.textContent = showValue ? "重新遮盖这处值" : "显示这处待核对值";
  reveal.setAttribute("aria-pressed", String(showValue));
  context.textContent = "";
  if (!focused) {
    title.textContent = "";
    return;
  }
  const { row, group } = focused;
  const first = Math.max(0, row.start - 72);
  const last = Math.min(points.length, Math.min(row.end, row.start + 160) + 72);
  let cursor = first;
  const content = first > 0 ? ["…"] : [];
  for (const doubt of data.doubts) {
    if (showValue && doubt === row) continue;
    const from = Math.max(cursor, doubt.start);
    const to = Math.min(last, doubt.end);
    if (to <= from) continue;
    content.push(points.slice(cursor, from).join(""), "〈待核对值已遮盖〉");
    cursor = to;
  }
  content.push(points.slice(cursor, last).join(""));
  if (last < points.length) content.push("…");
  title.textContent = entryLocation(row, group) + " · 候选片段";
  context.textContent = content.join("");
}

controls.addEventListener("change", () => {
  counts.doubts = counts.changes = PAGE;
  focused = null;
  showContext(false);
  renderLists();
});
for (const group of ["doubts", "changes"]) {
  document.getElementById(group + "-more").addEventListener("click", () => {
    counts[group] += PAGE;
    render(group);
  });
}
reveal.addEventListener("click", () => showContext(!showingValue));
file.addEventListener("change", async () => {
  const ticket = ++generation;
  const selected = file.files[0];
  points = focused = null;
  showContext(false);
  renderLists();
  if (!selected) {
    status.textContent = "选择对应副本后查看某一处候选片段。";
    return;
  }
  file.value = "";
  if (!globalThis.crypto?.subtle) {
    status.textContent = "浏览器无法校验副本，片段不可用。";
    return;
  }
  if (selected.size > data.maxBytes) {
    status.textContent = "文件超过预览上限，片段不可用。";
    return;
  }
  status.textContent = "正在本地校验副本…";
  try {
    const contents = await selected.arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", contents);
    const hash = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
    if (ticket !== generation) return;
    if (hash !== data.hash) {
      status.textContent = "副本不匹配。请选对应候选，或重新生成预览。";
      return;
    }
    const verified = Array.from(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(contents));
    if ([...data.doubts, ...data.changes].some(row => row.end > verified.length)) {
      status.textContent = "位置校验失败，片段不可用。";
      return;
    }
    points = verified;
    status.textContent = "副本校验通过。选择一项查看候选片段。";
    renderLists();
  } catch {
    if (ticket === generation) status.textContent = "无法读取或校验副本，片段不可用。";
  }
});
renderLists();
"""


def _validated_rows(rows, *, doubtful):
    keys = DOUBT_KEYS if doubtful else CHANGE_KEYS
    validated = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != keys:
            raise ValueError("INVALID_REVIEW_METADATA")
        kind = row["kind"]
        if not isinstance(kind, str) or kind not in TYPE_LABELS:
            raise ValueError("INVALID_REVIEW_METADATA")
        if any(type(row[key]) is not int for key in ("line", "column", "start", "end")):
            raise ValueError("INVALID_REVIEW_METADATA")
        if not (1 <= row["line"] <= MAX_FILE_BYTES and 1 <= row["column"] <= MAX_FILE_BYTES
                and 0 <= row["start"] < row["end"] <= MAX_FILE_BYTES):
            raise ValueError("INVALID_REVIEW_METADATA")
        if doubtful:
            if kind not in DOUBT_TYPES or row["reason"] != "UNMASKED_LABELED_VALUE":
                raise ValueError("INVALID_REVIEW_METADATA")
        elif not isinstance(row["marker"], str) or not re.fullmatch(rf"\[{kind}_[0-9]{{3,6}}\]", row["marker"]):
            raise ValueError("INVALID_REVIEW_METADATA")
        validated.append(row)
    return sorted(validated, key=lambda row: (row["start"], row["end"]))


def _integrity(text):
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def render_preview(changes, doubts, output_sha256, ordinary_types):
    """Write-only renderer. Arguments must contain no source or candidate text."""
    if not isinstance(output_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", output_sha256):
        raise ValueError("INVALID_REVIEW_METADATA")
    selected = set(ordinary_types)
    if not selected.issubset(ORDINARY_TYPES):
        raise ValueError("INVALID_REVIEW_METADATA")
    changes = _validated_rows(changes, doubtful=False)
    doubts = _validated_rows(doubts, doubtful=True)
    kinds = {row["kind"] for row in changes + doubts}
    options = "".join(f'<option value="{kind}">{TYPE_LABELS[kind]}</option>'
                      for kind in TYPE_LABELS if kind in kinds)
    excluded = "、".join(TYPE_LABELS[kind] for kind in TYPE_LABELS if kind in ORDINARY_TYPES - selected)
    notice = f'<p class="muted">普通敏感中未选择替换的类型：{excluded}。</p>' if excluded else ""
    payload = json.dumps({"changes": changes, "doubts": doubts, "hash": output_sha256,
                          "labels": TYPE_LABELS, "ordinary": sorted(ORDINARY_TYPES),
                          "maxBytes": MAX_FILE_BYTES}, ensure_ascii=True, separators=(",", ":"))
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src '{_integrity(SCRIPT)}'; style-src '{_integrity(STYLE)}'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>本地脱敏复核</title>
<style>{STYLE}</style>
</head>
<body>
<main>
  <header>
    <h1>本地脱敏复核</h1>
    <p class="summary">待核对 {len(doubts)} 项 · 已替换 {len(changes)} 项</p>
  </header>
  {notice}
  <div class="filters">
    <label for="filter">筛选类型</label>
    <select id="filter">
      <option value="all">全部</option><option value="high">高敏</option><option value="ordinary">普通敏感</option>
      {options}
    </select>
  </div>
  <div class="grid">
    <div>
      <section id="doubts" aria-labelledby="doubts-heading">
        <h2 id="doubts-heading">待核对</h2>
        <p class="muted" id="doubts-shown" aria-live="polite"></p>
        <ol id="doubts-rows"></ol>
        <button id="doubts-more" type="button" hidden>显示更多</button>
      </section>
      <section id="changes" aria-labelledby="changes-heading">
        <h2 id="changes-heading">已替换</h2>
        <p class="muted" id="changes-shown" aria-live="polite"></p>
        <ol id="changes-rows"></ol>
        <button id="changes-more" type="button" hidden>显示更多</button>
      </section>
    </div>
    <aside aria-labelledby="candidate-heading">
      <h2 id="candidate-heading">候选片段</h2>
      <label for="candidate">选择脱敏副本</label>
      <input id="candidate" type="file" accept=".txt,.md,.json,.log">
      <p class="muted" id="candidate-status" role="status">选择对应副本后查看某一处候选片段。</p>
      <p id="context-title" tabindex="-1"></p>
      <pre id="context" hidden></pre>
      <button id="reveal" type="button" hidden>显示这处待核对值</button>
    </aside>
  </div>
  <noscript>请在允许本地 JavaScript 的浏览器中打开，以显示复核列表。</noscript>
</main>
<script id="review-data" type="application/json">{payload}</script>
<script>{SCRIPT}</script>
</body>
</html>
"""
