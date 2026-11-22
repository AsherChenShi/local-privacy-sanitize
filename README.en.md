# local-privacy-sanitize

[中文](README.md)

Local text redaction with optional desktop plugin switches for Codex and Claude Code. The file tool uses the Python standard library to produce a candidate for local review while preserving relationships and key facts. The plugins inspect submitted text and selected tool results. The detector runs locally without sending text to a network service or a model.

Use macOS or Linux with Python 3.9+. The file tool accepts UTF-8 `.txt`, `.md`, and `.log` files up to 2 MiB. The fixtures are fictional.

## Install the file redaction skill

```sh
git clone https://github.com/AsherChenShi/local-privacy-sanitize.git
cd local-privacy-sanitize
python3 scripts/install_skill.py --target codex
python3 scripts/install_skill.py --target claude
```

Run the install command for the host you want to use. The installer copies the curated skill files to `$CODEX_HOME/skills/local-privacy-sanitize` (by default `~/.codex/skills/local-privacy-sanitize`) or `~/.claude/skills/local-privacy-sanitize`. If the destination already exists, the command stops. Open a new conversation if the host has yet to discover the skill. In Codex you can invoke `$local-privacy-sanitize` directly.

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

When enabled, `UserPromptSubmit` rejects prompts that match the rules. `PostToolUse` replaces matching Bash and supported MCP results in the model context. Use the file tool to prepare and review a redacted copy before resubmitting a blocked prompt. When the plugin is disabled, Claude Code follows its normal flow.

You can add a local entity dictionary at `~/.claude/local-privacy-sanitize/entities.local.json`. If you set `CLAUDE_CONFIG_DIR`, use the same path relative to that directory. See the [configuration format](references/privacy-boundary.md).

To test the switch, open a new local conversation in each mode and submit `Reply only TEST_OK. The fictional test email is desktop-test@example.invalid`. The enabled plugin should reject the prompt. With the plugin disabled, the prompt should receive a reply. Verify that the client loaded the plugin and hooks before relying on the check. [Claude Code desktop plugins](https://code.claude.com/docs/en/desktop#install-plugins) · [Claude Code Hooks](https://code.claude.com/docs/en/hooks#posttooluse-decision-control)

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
| URLs and connection strings | A match can cover the entire value, including public URLs |
| Names, organizations, addresses, project names | Literal entries in an optional local entity dictionary |
| Unconfigured names, indirect identifiers, business secrets | Require local review or another control |
| PDF, images, Office documents, audio, attachments | Use a separate control. The file tool accepts plain text |
| Codex prompt and supported tool result events | Optional local check and block |
| Claude Code prompt, Bash, and supported MCP result events | Optional prompt block and tool result replacement |

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
