"use strict";

const get = id => document.getElementById(id);
const source = get("source");
const result = get("result");
const file = get("file");
const format = get("format");
const dictionary = get("dictionary");
const generate = get("prepare");
const copy = get("copy");
const download = get("download");
const policyPanel = get("policy-panel");
const typeFieldset = get("ordinary-types");
const typeOptions = [...typeFieldset.querySelectorAll("input")];
const saveTypes = get("save-policy");
const key = location.hash.slice(1);
const maxBytes = 2 * 1024 * 1024;
const fileFormats = new Map([["txt", "text"], ["log", "text"], ["json", "json"], ["md", "markdown"]]);
const errors = {
  EMPTY_INPUT: "请粘贴文字或选择有效的文本文件。",
  FILE_TOO_LARGE: "内容超过 2 MiB，请在本机拆成较小的文件。",
  UTF8_REQUIRED: "请在本地编辑器将文件另存为 UTF-8，再选择文件。",
  UNSUPPORTED_FILE_TYPE: "请选择 TXT、LOG、JSON 或 Markdown 文件。",
  DICTIONARY_NOT_FOUND: "未找到所选词典。可配置该宿主的实体词典，或手动选择仅使用内置规则。",
  INVALID_POLICY: "实体词典无法读取或格式有误。请先在本机修正配置。",
  INVALID_REVIEW_POLICY: "普通敏感类型配置有误。请在本机修正 review-policy.local.json。",
  REVIEW_POLICY_CHANGED: "设置已在其他窗口更改。已重新读取，请重新选择并保存。",
  REVIEW_POLICY_BUSY: "另一个窗口正在保存。请稍后重试。",
  SESSION_REQUIRED: "预检会话不可用。请重新启动本地预检，从终端给出的地址打开。",
  RESERVED_PLACEHOLDER_IN_INPUT: "输入已含工具保留的占位符。请使用待处理的原始文本，或单独复检已有候选。",
  LOCAL_IO_OR_DATA_ERROR: "无法读取本地数据。请检查文件权限后重试。",
  INVALID_JSON: "JSON 格式有误。请在本机修正后重试。",
  DUPLICATE_JSON_KEY: "JSON 有重复键，请在本机处理后重试。",
  INVALID_REQUEST: "无法处理这段文字。请检查输入编码和格式。"
};
let generation = 0;
let fileText = null;
let candidate = null;
let savedTypes = null;
let loadingPolicy = false;
let savingPolicy = false;

function notify(message, error = false) {
  get("status").textContent = message;
  get("status").dataset.error = String(error);
}

function invalidate() {
  generation += 1;
  candidate = null;
  result.value = "";
  copy.disabled = true;
  download.disabled = true;
  generate.disabled = !key || savingPolicy;
  get("review").hidden = true;
  get("changes").replaceChildren();
  get("doubts").replaceChildren();
  return generation;
}

async function localRequest(route, body) {
  const response = await fetch(route, {
    method: "POST", credentials: "omit", cache: "no-store", redirect: "error",
    headers: {"Content-Type": "application/json", "X-Preflight-Key": key},
    body: JSON.stringify(body)
  });
  return {ok: response.ok, data: await response.json()};
}

function policyMessage(message, error = false) {
  const status = get("policy-status");
  status.textContent = message;
  status.dataset.error = String(error);
}

function checkedTypes() {
  return typeOptions.filter(option => option.checked).map(option => option.value).sort();
}

function fillTypes(selected) {
  savedTypes = [...selected].sort();
  for (const option of typeOptions) option.checked = savedTypes.includes(option.value);
  typeFieldset.disabled = false;
  saveTypes.disabled = true;
}

async function loadTypes() {
  if (loadingPolicy) return;
  savedTypes = null;
  typeFieldset.disabled = true;
  saveTypes.disabled = true;
  if (!key) return policyMessage(errors.SESSION_REQUIRED, true);
  loadingPolicy = true;
  policyMessage("正在读取本地设置…");
  try {
    const {ok, data} = await localRequest("/policy/read", {});
    if (!ok) return policyMessage(errors[data.code] || "无法读取类型设置。", true);
    fillTypes(data.ordinary_types);
    policyMessage("");
  } catch {
    policyMessage("无法读取类型设置。请确认本地预检还在运行。", true);
  } finally {
    loadingPolicy = false;
  }
}

policyPanel.addEventListener("toggle", () => {
  if (policyPanel.open && !savingPolicy) loadTypes();
});
typeFieldset.addEventListener("change", () => {
  saveTypes.disabled = !savedTypes || JSON.stringify(checkedTypes()) === JSON.stringify(savedTypes);
});
saveTypes.addEventListener("click", async () => {
  if (!savedTypes || savingPolicy) return;
  const chosen = checkedTypes();
  savingPolicy = true;
  invalidate();
  typeFieldset.disabled = true;
  saveTypes.disabled = true;
  try {
    const {ok, data} = await localRequest("/policy/save", {ordinary_types: chosen, previous: savedTypes});
    if (!ok) {
      if (data.code === "REVIEW_POLICY_CHANGED") await loadTypes();
      return policyMessage(errors[data.code] || "未保存类型设置。", true);
    }
    fillTypes(data.ordinary_types);
    policyMessage("已保存到本机。");
    notify("类型已更新，请重新生成候选。");
  } catch {
    await loadTypes();
    policyMessage("未能确认保存状态。请检查当前勾选。", true);
  } finally {
    savingPolicy = false;
    invalidate();
    typeFieldset.disabled = !savedTypes;
    saveTypes.disabled = !savedTypes || JSON.stringify(checkedTypes()) === JSON.stringify(savedTypes);
  }
});

function clear() {
  invalidate();
  source.value = "";
  file.value = "";
  fileText = null;
  notify("已清空原文和候选。");
}

function inputChanged() {
  invalidate();
  notify("内容有变化，请重新生成候选。");
}

source.addEventListener("input", () => {
  fileText = null;
  file.value = "";
  inputChanged();
});
format.addEventListener("change", inputChanged);
dictionary.addEventListener("change", inputChanged);
get("clear").addEventListener("click", clear);
window.addEventListener("pagehide", clear);

file.addEventListener("change", async () => {
  const selected = file.files[0];
  if (!selected) return;
  const current = invalidate();
  source.value = "";
  fileText = null;
  const suffix = selected.name.split(".").pop().toLowerCase();
  if (!selected.name.includes(".") || !fileFormats.has(suffix) || selected.size > maxBytes) {
    file.value = "";
    return notify(errors[selected.size > maxBytes ? "FILE_TOO_LARGE" : "UNSUPPORTED_FILE_TYPE"], true);
  }
  generate.disabled = true;
  notify("正在读取本机文件…");
  try {
    const bytes = await selected.arrayBuffer();
    if (current !== generation) return;
    fileText = new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(bytes);
    source.value = fileText;
    format.value = fileFormats.get(suffix);
    notify("文件已加载，可以生成候选。");
  } catch {
    if (current !== generation) return;
    file.value = "";
    notify(errors.UTF8_REQUIRED, true);
  } finally {
    if (current === generation) generate.disabled = !key || savingPolicy;
  }
});

function displayOffset(text, codePoints) {
  // Python locations count code points. Textareas count UTF-16 and collapse CRLF.
  let offset = 0;
  let previousWasCR = false;
  for (const point of text) {
    if (codePoints-- === 0) break;
    if (point !== "\n" || !previousWasCR) offset += point.length;
    previousWasCR = point === "\r";
  }
  return offset;
}

function reviewRows(group, rows, total, labels) {
  const title = group === "changes" ? "已替换" : "待核对";
  get(group + "-title").textContent = `${title} ${total} 处`;
  const list = get(group);
  for (const row of rows) {
    const item = document.createElement("li");
    const location = group === "changes" ? "原文" : "候选";
    item.textContent = `${location}第 ${row.line} 行，第 ${row.column} 列 · ${labels[row.kind] || row.kind}`
      + (group === "changes" ? ` → ${row.marker}` : "有未遮盖的标注值");
    const locate = document.createElement("button");
    locate.type = "button";
    locate.textContent = "在候选中定位";
    locate.addEventListener("click", () => {
      if (!candidate) return;
      result.focus();
      result.setSelectionRange(displayOffset(candidate.candidate, row.start), displayOffset(candidate.candidate, row.end));
    });
    item.append(locate);
    list.append(item);
  }
  if (total === 0 || total > rows.length) {
    const item = document.createElement("li");
    item.textContent = total ? `显示前 ${rows.length} 处。` : "当前规则没有提示。";
    list.append(item);
  }
}

generate.addEventListener("click", async () => {
  const current = invalidate();
  const text = fileText ?? source.value;
  if (!text.trim()) return notify(errors.EMPTY_INPUT, true);
  if (text.length > maxBytes || new TextEncoder().encode(text).length > maxBytes) {
    return notify(errors.FILE_TOO_LARGE, true);
  }
  generate.disabled = true;
  notify("正在本机检查…");
  try {
    const {ok, data} = await localRequest("/prepare", {text, format: format.value, dictionary: dictionary.value});
    if (current !== generation) return;
    if (!ok) {
      return notify(errors[data.code] || "未生成候选。请检查所选格式和原文结构，修正后重试。", true);
    }
    if (data.status !== "REVIEW_REQUIRED" || typeof data.candidate !== "string") {
      throw new Error("Invalid local response");
    }
    reviewRows("changes", data.changes, data.change_count, data.labels);
    reviewRows("doubts", data.doubts, data.doubt_count, data.labels);
    get("review").hidden = false;
    candidate = data;
    result.value = candidate.candidate;
    copy.disabled = false;
    download.disabled = false;
    notify(`候选待复核。替换 ${data.change_count} 处，待核对 ${data.doubt_count} 处。`);
  } catch {
    if (current === generation) notify("本地检查未完成。请确认预检仍在运行，再重试。", true);
  } finally {
    if (current === generation) generate.disabled = !key || savingPolicy;
  }
});

copy.addEventListener("click", async () => {
  if (!candidate) return;
  const current = generation;
  try {
    await navigator.clipboard.writeText(candidate.candidate);
    if (current === generation) notify("已复制候选。请在确认可以发送后粘贴到 AI。");
  } catch {
    if (current !== generation) return;
    result.select();
    notify("浏览器未允许自动复制，请使用系统复制快捷键。", true);
  }
});

download.addEventListener("click", () => {
  if (!candidate) return;
  const url = URL.createObjectURL(new Blob([candidate.candidate], {type: "text/plain;charset=utf-8"}));
  const link = document.createElement("a");
  link.href = url;
  link.download = candidate.artifact;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

if (!key) {
  generate.disabled = true;
  notify(errors.SESSION_REQUIRED, true);
}
