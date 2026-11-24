/* Optional real-browser smoke test. Uses an isolated Chromium and synthetic input. */
"use strict";

const assert = require("node:assert/strict");
const {spawn} = require("node:child_process");
const {mkdir, mkdtemp, readFile, rm, writeFile} = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");
const {chromium} = require("playwright");

const script = process.argv[2] || path.join(__dirname, "../scripts/preflight.py");
const email = "browser-preflight@example.invalid";

async function startup(child) {
  const lines = readline.createInterface({input: child.stdout});
  let timeout;
  try {
    return await Promise.race([
      new Promise((resolve, reject) => {
        lines.once("line", line => {
          const match = line.match(/http:\/\/127\.0\.0\.1:\d+\/#[-_a-zA-Z0-9]+$/);
          if (match) resolve(match[0]);
          else reject(new Error("Preflight did not emit its local URL"));
        });
        child.once("error", reject);
        child.once("exit", code => reject(new Error(`Preflight exited with ${code}`)));
      }),
      new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error("Preflight did not start")), 8000); })
    ]);
  } finally {
    clearTimeout(timeout);
    lines.close();
  }
}

async function run() {
  const home = await mkdtemp(path.join(os.tmpdir(), "privacy-preflight-test-"));
  const codexHome = path.join(home, "codex");
  const dictionaryDir = path.join(codexHome, "local-privacy-sanitize");
  await mkdir(dictionaryDir, {recursive: true});
  await writeFile(path.join(dictionaryDir, "entities.local.json"),
    JSON.stringify({entities: [{type: "PERSON", values: ["虚构姓名"]}]}));
  const child = spawn(process.env.PREFLIGHT_PYTHON || "python3", [script, "--no-open"], {
    env: {...process.env, HOME: home, CODEX_HOME: codexHome}, stdio: ["ignore", "pipe", "inherit"]
  });
  const stopped = new Promise(resolve => child.once("close", resolve));
  let browser;
  try {
    const url = await startup(child);
    const origin = new URL(url).origin;
    browser = await chromium.launch({executablePath: process.env.PREFLIGHT_CHROMIUM || undefined});
    const page = await browser.newPage({viewport: {width: 1100, height: 850}});
    const outbound = [];
    await page.route("**/*", route => {
      if (new URL(route.request().url()).origin === origin) return route.continue();
      outbound.push(route.request().url());
      return route.abort();
    });
    await page.addInitScript(() => {
      Object.defineProperty(navigator, "clipboard", {value: {
        writeText(value) { window.testCopied = value; return Promise.resolve(); }
      }});
    });
    await page.goto(url);
    await page.getByRole("heading", {name: "本地隐私预检"}).waitFor();
    const input = page.getByRole("textbox", {name: "原文"});
    const result = page.getByRole("textbox", {name: "待复核候选"});
    const prepare = page.getByRole("button", {name: "生成候选"});
    const copy = page.getByRole("button", {name: "复制候选"});
    await input.fill(`测试邮箱 ${email}\n联系人：虚构姓名\n保持 2 次失败`);
    await prepare.click();
    await page.getByRole("heading", {name: "已替换 1 处"}).waitFor();
    assert.match(await page.locator("#changes").innerText(), /原文第 1 行，第 6 列/);
    assert.match(await page.locator("#doubts").innerText(), /候选第 2 行/);
    assert.equal(await result.inputValue(), "测试邮箱 [EMAIL_001]\n联系人：虚构姓名\n保持 2 次失败");
    await copy.click();
    assert.equal(await page.evaluate(() => window.testCopied), await result.inputValue());

    await page.locator("#dictionary").selectOption("codex");
    await prepare.click();
    await page.getByRole("heading", {name: "已替换 2 处"}).waitFor();
    await page.getByText("普通敏感类型设置", {exact: true}).click();
    const person = page.getByRole("checkbox", {name: "姓名", exact: true});
    await page.waitForFunction(() => !document.querySelector("#ordinary-types").disabled);
    assert.equal(await person.isChecked(), true);
    await person.uncheck();
    assert.equal(await copy.isEnabled(), true);
    await page.getByRole("button", {name: "保存类型"}).click();
    await page.getByText("已保存到本机。", {exact: true}).waitFor();
    assert.equal(await copy.isDisabled(), true);
    await prepare.click();
    await page.getByRole("heading", {name: "已替换 1 处"}).waitFor();
    assert.equal(await result.inputValue(), "测试邮箱 [EMAIL_001]\n联系人：虚构姓名\n保持 2 次失败");
    if (process.env.PREFLIGHT_SCREENSHOT) await page.screenshot({path: process.env.PREFLIGHT_SCREENSHOT, fullPage: true});
    await page.reload();
    const settings = page.getByText("普通敏感类型设置", {exact: true});
    if (!await page.locator("#policy-panel").evaluate(panel => panel.open)) await settings.click();
    await person.waitFor();
    await page.waitForFunction(() => !document.querySelector("#ordinary-types").disabled);
    assert.equal(await person.isChecked(), false);
    assert.equal(await page.getByRole("checkbox", {name: "地址", exact: true}).isChecked(), true);
    await input.fill("new draft");
    assert.equal(await result.inputValue(), "");
    assert.equal(await copy.isDisabled(), true);

    const markdown = `| contact |\r\n| --- |\r\n| 🔎 ${email} |\r\n`;
    await page.locator("#file").setInputFiles({name: "fixture.md", mimeType: "text/plain", buffer: Buffer.from(markdown)});
    await page.getByText("文件已加载，可以生成候选。").waitFor();
    await prepare.click();
    await page.getByRole("heading", {name: "已替换 1 处"}).waitFor();
    await page.getByRole("button", {name: "在候选中定位"}).click();
    assert.equal(await result.evaluate(box => box.value.slice(box.selectionStart, box.selectionEnd)), "[EMAIL_001]");
    const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", {name: "下载候选"}).click()]);
    assert.equal(download.suggestedFilename(), "sanitized.md");
    assert.equal(await readFile(await download.path(), "utf8"), markdown.replace(email, "[EMAIL_001]"));

    await input.fill('{"bad":');
    await page.locator("#format").selectOption("json");
    await prepare.click();
    await page.locator("#status[data-error=true]").waitFor();
    assert.equal(await copy.isDisabled(), true);
    assert.equal(await result.inputValue(), "");
    await page.locator("#format").selectOption("text");
    await input.fill("<img src=https://blocked.invalid/p onerror=alert(1)>");
    await prepare.click();
    await page.getByRole("heading", {name: "已替换 1 处"}).waitFor();
    assert.equal(await page.locator("img").count(), 0);
    await page.setViewportSize({width: 390, height: 820});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.getByRole("button", {name: "清空"}).click();
    assert.equal(await input.inputValue(), "");
    assert.equal(await result.inputValue(), "");
    assert.equal(await copy.isDisabled(), true);
    assert.deepEqual(outbound, []);
    console.log("Preflight browser smoke passed.");
  } finally {
    if (browser) await browser.close();
    child.kill("SIGINT");
    await stopped;
    await rm(home, {recursive: true, force: true});
  }
}

run().catch(error => { console.error(error); process.exitCode = 1; });
