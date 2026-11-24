# local-privacy-sanitize

[中文](README.md)

Local text redaction with optional desktop plugin switches for Codex and Claude Code. The file tool uses the Python standard library to produce a candidate for local review while preserving relationships and key facts. The plugins inspect submitted text and selected tool results. The detector runs locally without sending text to a network service or a model.

Use macOS or Linux with Python 3.9+. The tool accepts UTF-8 `.txt`, `.log`, `.json`, and `.md` files up to 2 MiB. The fixtures are fictional. [Data flow and architecture](references/architecture.md)

## Quick start

Use the standalone preflight before sharing text or a file with any AI client. On macOS, double-click `open-preflight.command` in the repository or the extracted plugin directory. On macOS or Linux, you can also run:

```sh
python3 scripts/preflight.py
```

Paste text or choose a TXT, LOG, JSON, or Markdown file, then select **生成候选** (Generate candidate). Review the highlighted categories and locations, then select **复制候选** (Copy candidate) or **下载候选** (Download candidate). The window currently has Chinese labels. It uses built-in rules by default. If you already set up an entity dictionary, select the corresponding host. Close the launcher or press `Ctrl+C` to stop the local process.

The standalone window works without the plugins. With either plugin enabled, you can open the same preflight after a blocked prompt and then resubmit the reviewed candidate yourself. Everyday messages do not open a window. The browser page connects only to the local process. The program does not write input or candidates to disk. Copying and downloading use the system clipboard and browser download location. [Privacy boundary](references/privacy-boundary.md#本地预检窗口) · [Usability review and implementation notes](references/personal-use-review.md)

## Install the file redaction skill

```sh
git clone https://github.com/AsherChenShi/local-privacy-sanitize.git
cd local-privacy-sanitize
python3 scripts/install_skill.py --target codex
python3 scripts/install_skill.py --target claude
```

Run the install command for the host you want to use. The installer reads `CODEX_HOME` or `CLAUDE_CONFIG_DIR` and installs to `skills/local-privacy-sanitize` inside that directory. The defaults are `~/.codex` and `~/.claude`. If the destination already exists, the command stops. Open a new conversation if the host has yet to discover the skill. In Codex you can invoke `$local-privacy-sanitize` directly.

The optional one-time email-fill lab supports HTTPS loopback test sites and synthetic `.invalid` addresses. [One-time email authorization lab](references/signup-lab.md)

## Switch protection in Codex Desktop

1. From the repository root, run `python3 scripts/build_codex_plugin.py outputs/codex-privacy-desktop`. This creates a marketplace folder and a ZIP with the same name. If you received a ZIP, extract it instead.
2. Open the extracted `codex-privacy-desktop` folder as a Codex project. Restart the desktop app to load the local marketplace. Open **Plugins → 本地隐私工具** (Local Privacy Tools) and install **脱敏保护** (Privacy Protection).
3. In **Settings → Hooks**, review and trust the plugin's two hooks. Then use **Plugins → 脱敏保护** to turn both checks on or off. Open a new local conversation after switching to verify which mode is active.

When the plugin is enabled and trusted, it blocks text or supported tool results that match the detector's rules. Use the file tool to make a redacted copy, review it locally, and resubmit it. If you previously enabled the terminal-managed Codex hooks, run `python3 scripts/codex_privacy.py off` once before using the desktop plugin to avoid running both sets of hooks. The two switches are independent. [OpenAI local plugin documentation](https://developers.openai.com/plugins/build/plugins#how-local-marketplaces-work)

## Switch protection in Claude Code Desktop

Use Claude Code 2.1.295 or newer with a working local Code session and host support for `updatedToolOutput`. Install the file redaction skill separately if you want to use it from the agent.

If the desktop **Code** tab only shows **Get Claude Code**, check whether your account can start a local Code session. The Free account used for desktop inspection showed only this entry point.

`onFailure: "block"` is used to reject prompt submission if its check fails. Tool output is replaced only when the hook returns successfully and Claude accepts the replacement. A crash, timeout, or rejected replacement may leave the original tool result in context.

1. From the repository root, run `python3 scripts/build_claude_plugin.py outputs/claude-privacy-desktop`. This creates the marketplace folder and a ZIP. If you received a ZIP, extract it instead.
2. In the Claude desktop app, open **Code**, start a **Local** session, and select this repository folder. Enter `/plugin marketplace add ./outputs/claude-privacy-desktop` in the session. If you extracted the package elsewhere, use the actual directory path. For one-time setup from a terminal, you can also run `claude plugin marketplace add ./outputs/claude-privacy-desktop`.
3. Use **+ → Add plugins** or **+ → Plugins → Browse plugins** near the composer to find and install `claude-privacy` (`claude-privacy@local-privacy-tools`). Choose the scope you want. You can also enter `/plugin install claude-privacy@local-privacy-tools` in a Claude Code session.
4. For everyday use, open **+ → Plugins → Manage plugins** or **Customize / Plugins** in the local session sidebar. Enable or disable the plugin, then start a new local Code conversation to verify the setting. The CLI also offers the **Installed** tab under `/plugin`. Your account must be able to start a Claude Code session. Check the **Code** tab in your app.

When enabled, `UserPromptSubmit` rejects prompts that match the rules. `PostToolUse` checks Bash, built-in `Read` text results, and supported MCP results. When replacement succeeds, the next model request receives the replacement. Prepare and review a redacted copy locally before resubmitting a blocked prompt. When the plugin is disabled, Claude Code follows its normal flow.

To deny built-in `Read` before it opens originals, configure absolute directory paths. The rule applies to files in those directories and their subdirectories. Bash and other tools retain their own permissions. [Protected directory setup](references/privacy-boundary.md#claude-code-内置-read-保护)

You can add a local entity dictionary at `~/.claude/local-privacy-sanitize/entities.local.json`. If you set `CLAUDE_CONFIG_DIR`, use the same path relative to that directory. See the [configuration format](references/privacy-boundary.md).

To test the switch, open a new local conversation in each mode and submit `Reply only TEST_OK. The fictional test email is desktop-test@example.invalid`. The enabled plugin should reject the prompt. With the plugin disabled, the prompt should receive a reply. Verify that the client loaded the plugin and hooks before relying on the check. [Claude Code desktop plugins](https://code.claude.com/docs/en/desktop#install-plugins) · [Claude Code Hooks](https://code.claude.com/docs/en/hooks#posttooluse-decision-control)

## Link checks and plugin updates

You can keep protection enabled during routine work. HTTPS links for GitHub browsing, API calls, raw files, and official documentation pass the URL check when they match the rules. File redaction and checking use the same policy. Links with tokens, signatures, credentials, or redirect parameters still trigger the detector, as do internal or ambiguous links. Other rules still check nearby text and the URL itself. Offline checks cannot tell whether a normal-looking repository link points to a private repository. See the [link rules](references/privacy-boundary.md#链接检查规则).

The phone rule skips the run ID in eligible GitHub Actions links. The same digits in ordinary text still undergo the phone check. Redacting a Markdown link preserves its label and closing parenthesis. Both plugins check clear credential fields such as `access_token`, `password`, and `Authorization` together with their JSON values. Ordinary metrics such as `token_count` can pass.

If you already installed a plugin, update the checkout and run its build command with a new output directory. Point the local marketplace at the new bundle, then reinstall the plugin from that updated source to refresh the host's cached copy. Updating the checkout alone leaves the installed copy in place. Choose whether to enable it in the host and review any hook prompt. Update the file redaction skill separately from the plugins.

In a new local session with protection enabled, verify the two prompts below. The first link should pass the URL check. The second uses a fictional token and should be blocked.

```text
Describe this public project https://github.com/AsherChenShi/local-privacy-sanitize
Check this link with a fictional token https://github.com/AsherChenShi/local-privacy-sanitize?token=SYNTHETIC_ONLY
```

## Inspect local plugin status

Run the relevant command from the repository root. Each plugin bundle also includes `scripts/privacy_status.py` inside its plugin directory.

```sh
python3 scripts/privacy_status.py codex
python3 scripts/privacy_status.py claude --project .
```

The report shows local installation records or cached versions, configured switches, visible hook settings, and recorded trust evidence. For Claude Code, pass the client version with `--runtime-version` to compare it with the documented minimum for blocking on hook failure. The script reads local files without starting the host or changing settings. `protection_status: not_protected` means a check is configured off. `unverified` means configuration alone does not establish that the session is protected. With `hook_execution: not_verified`, verify a new local session using the fictional `expect_pass` and `expect_block` prompts. Use the command in `local_preflight` while protection is off or unverified.

A running supervisor gives the check process up to six seconds. The host hook timeout remains ten seconds. A stalled check, worker crash, or invalid result produces a fixed response. Codex can still send when the host skips the hook or terminates it first. Treat that session as unprotected and prepare sensitive material with the independent local preflight. On supported versions of Claude Code, `onFailure: "block"` covers failure of a configured prompt hook. Tool result protection depends on the host accepting the replacement. [OpenAI Hooks documentation](https://learn.chatgpt.com/docs/hooks) · [Claude Code failure handling](https://code.claude.com/docs/en/hooks#block-the-action-when-a-hook-fails)

## Codex terminal controls

The terminal setup is independent of skill installation and of the desktop plugin. Registration starts with protection disabled.

```sh
python3 scripts/codex_privacy.py install
python3 scripts/codex_privacy.py status
python3 scripts/codex_privacy.py on
python3 scripts/codex_privacy.py off
```

After registration, review and trust the two `local-privacy-sanitize` hooks under **Settings → Hooks** or `/hooks`. The `hooks_registered` field confirms that the definitions were written. Check the host for the trust state. Each invocation reads the current mode. `off` updates the mode file and leaves other hooks alone. Keep this checkout at the same location because registration references the absolute script path.

For Codex, either setup can use a local entity dictionary in `local-privacy-sanitize/entities.local.json` inside the Codex config directory (`~/.codex` by default or `$CODEX_HOME`). See the [configuration format](references/privacy-boundary.md). [OpenAI Hooks documentation](https://learn.chatgpt.com/docs/hooks)

## Run the independent local preflight

Process sensitive material outside the client. The preflight runs independently of either host and its hooks. Keep the original and any local dictionary where the agent cannot read them. Replace the example input path with your local file.

```sh
mkdir -p out
python3 scripts/sanitize.py sanitize --input private/request.json --out-dir out/request
python3 scripts/sanitize.py check --input out/request/sanitized.json
```

JSON produces `sanitized.json`, Markdown produces `sanitized.md`, and `.txt` and `.log` default to `sanitized.txt`. For structured material saved as `.txt` or `.log`, pass `--format json` or `--format markdown` to `sanitize`. Review the candidate and `report.json` locally, then submit only the candidate you approve.

JSON redaction replaces matching string values while preserving keys, nesting, array order, and unchanged number tokens. Markdown redaction preserves supported inline links, tables, and fences. Fences marked `json` use the same JSON processing. If the format is invalid, a match cannot be replaced reliably, or the candidate fails validation, the tool blocks candidate creation. [Format and privacy boundary](references/privacy-boundary.md#结构化预检)

### Preview local changes

Add `--preview` to `sanitize` and open `review.html` from the output directory in a browser. Both plugin bundles include the same preflight tool.

```sh
mkdir -p out
python3 scripts/sanitize.py sanitize --input private/request.json \
  --out-dir out/request-preview --preview
```

The page lists replacements and items to review. Filter replacements by sensitivity or type. Replacement locations refer to the original, and review item locations refer to the candidate. To see context, select the `sanitized.*` file from this run. The browser checks its SHA-256 locally before displaying the selected area. The generated HTML contains neither the original text nor the candidate body and works offline. Zero review items means the current rules raised no flags. [Preview and sensitivity configuration](references/privacy-boundary.md#本地预览和敏感级别)

### Configure standard sensitivity categories

Open **普通敏感类型设置** (Standard sensitivity settings) in the preflight window, choose the dictionary categories to redact, and select **保存类型** (Save categories). All four categories start enabled. The preflight and both enabled hooks read the shared setting on the next check. High-sensitivity rules are always applied. Saving clears the current candidate so you can regenerate it using the new selection.

You can also edit `~/.config/local-privacy-sanitize/review-policy.local.json` directly. For example, `{"ordinary_types":["PERSON","LOCATION"]}` redacts configured people and locations and keeps matches found only under organizations or projects.

To use another policy for a single preflight, pass the same `--review-policy PATH` to `sanitize` and `check`. That argument applies to the CLI, and the hooks continue to use the shared policy. Preview filters only change the visible list. Retained standard categories are summarized once. [Policy file and high-sensitivity boundary](references/privacy-boundary.md#本地预览和敏感级别)

## Try the fictional file example

```sh
mkdir -p out
python3 scripts/sanitize.py sanitize \
  --input examples/input.example.txt \
  --policy examples/entities.example.json \
  --out-dir out/demo

python3 scripts/sanitize.py check \
  --input out/demo/sanitized.txt \
  --policy examples/entities.example.json
```

Pick a new output directory for each run. `sanitize` returns `REVIEW_REQUIRED` and writes `sanitized.txt` and `report.json`. `check` may return `NO_KNOWN_MATCHES`. Both outcomes still require local review. The candidate and report use mode `0600`, and the output directory uses `0700`.

The [expected example output](examples/output.expected.txt) shows that people and organizations are replaced with stable placeholders within one file. Unchanged text keeps its original punctuation, dates, amounts, and negations. Those details can still identify people or reveal confidential work.

For real material, keep the original and any entity dictionary in a location the agent cannot read. Run the tool locally, review the candidate for missed matches or identifying combinations, and submit only the version you approve. The CLI prints category counts and keeps original values and replacement mappings out of its output. Exit code `0` means the operation completed and a review is still needed. Code `2` signals a block or failure. Code `3` means `check` found known matches.

## Coverage

| Data or path | Handling |
| --- | --- |
| Common email addresses, mainland China mobile numbers, ID-like values, some payment cards, IP addresses | Built-in rules and typed placeholders |
| Some credential formats and labeled secrets | Rule-based detection |
| URLs and connection strings | Eligible HTTPS links pass the URL check. A match can cover an entire value that fails the link rules |
| Names, organizations, addresses, project names | Literal entries in an optional local entity dictionary |
| Unconfigured names, indirect identifiers, business secrets | Require local review or another control |
| JSON and common Markdown structures | Local candidate generation and validation in the original format |
| PDF, images, Office documents, audio, attachments | Use a separate control |
| Codex prompt and supported tool result events | Optional local check and block |
| Claude Code prompt, Bash, built-in `Read` text results, and supported MCP results | Optional prompt block and supported tool result replacement |

Tool result replacement controls what the model sees after a tool runs. Commands that have already executed, network requests that have already left the machine, and host telemetry captured before a hook can still contain the original values. A hook that has yet to load, an unsupported tool result format, attachments, existing conversation context, and unhandled routes require separate controls. Keep highly sensitive originals in an environment with appropriate access restrictions.

## Develop and verify

```sh
python3 -m unittest discover -s tests -v
python3 scripts/validate_release.py
python3 -m compileall -q -b scripts tests
git diff --check
```

With Codex CLI installed, `python3 tests/codex_smoke.py` tests the terminal setup against a loopback server using fictional values. Add `--plugin` to test the native Codex plugin switch on a compatible engine. See [VALIDATION.md](VALIDATION.md) for the environments and paths actually tested. The tests cover defined cases. The detector and the `check` command share the same rules.

This repository does not specify an open-source license. Contact the repository owner for redistribution or derivative work permissions.
