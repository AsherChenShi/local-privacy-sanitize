# local-privacy-sanitize

[English](README.en.md)

为 Codex 和 Claude Code 提供本地文本脱敏与可选的桌面插件开关。文件工具用 Python 标准库生成**待本地复核**的副本，保留实体关系与关键事实。两个插件可检查即将提交的文字和各宿主支持的工具结果。检测程序不调用网络或外部模型。

支持 macOS/Linux、Python 3.9+、UTF-8 `.txt` / `.md` / `.log`，单文件不超过 2 MiB。所有仓库示例和测试数据均为虚构，不来自真实用户资料。

## 安装文件脱敏 skill

```bash
git clone https://github.com/AsherChenShi/local-privacy-sanitize.git
cd local-privacy-sanitize
python3 -m unittest discover -s tests -v
python3 scripts/validate_release.py

# 默认安装到 ${CODEX_HOME:-~/.codex}/skills/local-privacy-sanitize
python3 scripts/install_skill.py --target codex

# 可选：安装到 ~/.claude/skills/local-privacy-sanitize
python3 scripts/install_skill.py --target claude
```

安装器只复制明确列出的 skill 文件，不复制 Git 历史、测试、示例或用户数据。目标已存在时会停止，不覆盖已有配置。安装后如客户端未发现新技能，重新开启会话。Codex 可显式调用 `$local-privacy-sanitize`；其他宿主的发现与调用方式以其当前文档为准。

## 在 Codex 桌面界面切换

用本地插件「脱敏保护」一起控制提交文本检查和工具结果检查。安装一次后，日常只操作 Codex 的插件开关。插件适用于 macOS/Linux 上的本地 Codex，需要桌面运行环境能找到 Python 3.9+。

1. 将仓库打包为本地插件目录。运行 `python3 scripts/build_codex_plugin.py outputs/codex-privacy-desktop`，会生成目录和同名 ZIP。收到 ZIP 的用户可以直接解压。
2. 在 Codex 打开解压得到的 `codex-privacy-desktop` 文件夹作为项目。重启桌面应用以加载本地来源。在 **Plugins → 本地隐私工具** 中安装「脱敏保护」。
3. 在 **Settings → Hooks** 审核并信任该插件的两条检查。需要保护时在 **Plugins → 脱敏保护** 启用，普通会话中则可禁用。切换后用新的本地聊天确认状态。

启用且信任后，命中敏感规则时客户端拦截。需要改写时，用本地脱敏工具生成副本，复核后再提交。禁用此插件会停止它的两条检查。

如果以前启用了终端版，请先用 `python3 scripts/codex_privacy.py off` 关闭旧模式，避免两套配置同时检测。插件开关与旧版模式文件独立。两种接入共用可选的本地实体词典。 [OpenAI 本地插件说明](https://developers.openai.com/plugins/build/plugins#how-local-marketplaces-work)

## 在 Claude Code 桌面界面切换

需要能启动本地 Code 会话的 Claude Code 2.1.295 或更新版本，且宿主支持 `updatedToolOutput`。文件脱敏 skill 与此插件分别安装。

如果桌面端 **Code** 标签页只显示「获取 Claude Code」，请先确认账号可以启动本地 Code 会话。本机 Free 账号只能看到这个入口。

`onFailure: "block"` 用于提示词检查出错时拒绝提交。工具结果只有在 Hook 成功返回且 Claude 接受替换值时才会被替换。若工具检查异常退出、超时或宿主拒绝替换，原结果仍可能进入上下文。

1. 在仓库根目录运行 `python3 scripts/build_claude_plugin.py outputs/claude-privacy-desktop`。脚本生成本地插件目录和同名 ZIP。收到 ZIP 时直接解压即可。
2. 在 Claude 桌面端打开 **Code**，开始一个 **Local** 会话，并选中仓库目录。在会话里输入 `/plugin marketplace add ./outputs/claude-privacy-desktop`。如果解压到了其他目录，使用该目录的实际路径。也可在一次性的终端设置中运行 `claude plugin marketplace add ./outputs/claude-privacy-desktop`。
3. 选择输入框旁的 **+ → Add plugins**，或 **+ → Plugins → Browse plugins**，找到 `claude-privacy`（`claude-privacy@local-privacy-tools`）并安装，按需要选择用户或项目范围。也可在 Claude Code 会话输入 `/plugin install claude-privacy@local-privacy-tools`。
4. 之后在桌面端 **+ → Plugins → Manage plugins**，或本地会话侧栏的 **Customize / Plugins**，启用或禁用该插件。切换后新开一个本地 Code 会话确认。CLI 会话也可用 `/plugin` 的 **Installed** 标签页切换。该入口需要账号能够启动 Claude Code 会话，具体以桌面 **Code** 标签页显示为准。

启用后，`UserPromptSubmit` 拒绝命中规则的提示词。`PostToolUse` 替换命中的 Bash 和受支持的 MCP 返回，后续模型请求收到的是替换后的结果。需要发送原文的改写版时，先用下方文件工具在本机生成并复核副本。禁用插件后，Claude Code 按常规流程处理。

可在 `~/.claude/local-privacy-sanitize/entities.local.json` 添加本地实体词典。设置了 `CLAUDE_CONFIG_DIR` 时，从该目录下的同一相对路径读取。格式见 [配置与安全边界](references/privacy-boundary.md)。

测试切换时，只使用虚构数据。分别启用、禁用插件，各开一个新会话并发送 `只回复 TEST_OK。测试邮箱是 desktop-test@example.invalid`。启用时应被拒绝，禁用时应能正常收到回复。客户端必须实际加载插件和 Hooks，才能依赖这项检查。[Claude Code 桌面插件](https://code.claude.com/docs/en/desktop#install-plugins) · [Claude Code Hooks](https://code.claude.com/docs/en/hooks#posttooluse-decision-control)

## 链接检查与插件更新

日常可以保持保护开启。符合规则的 HTTPS GitHub 浏览、API、原始文件及官方文档链接可通过 URL 检查，文件脱敏和复检也使用同一套规则。带令牌、签名、登录信息或重定向参数的链接，以及内网和不明确的链接，仍会命中。公开链接旁的邮箱和凭据等内容会分别检查。离线检查无法判断一个外观正常的仓库链接对应公开还是私有仓库。具体匹配条件见 [链接检查规则](references/privacy-boundary.md#链接检查规则)。

符合条件的 GitHub Actions 运行编号按链接中的编号处理，同一个号码出现在普通正文时仍会接受手机号检查。脱敏 Markdown 链接时，链接标题和闭合括号会保留。两个插件也会结合 JSON 的字段名和值检查 `access_token`、`password`、`Authorization` 等明确的凭据字段，`token_count` 等普通统计仍可通过。

如果已经安装插件，请先更新仓库，用上面的构建命令生成新包。每次构建请选用尚不存在的输出目录。用新版目录更新本地插件来源，再从更新后的来源重新安装对应插件，以刷新宿主缓存。只更新仓库不会替换已安装的副本。在各自的插件界面选择是否启用，出现 Hook 审核提示时重新审核。文件脱敏 skill 与两个宿主插件分别更新。

在启用保护的新本地会话中，可以用下面这两条文本复验。第一条应通过 URL 检查，第二条使用虚构令牌，应被拦截。

```text
请说明这个公开项目的用途：https://github.com/AsherChenShi/local-privacy-sanitize
测试这个含虚构令牌的链接：https://github.com/AsherChenShi/local-privacy-sanitize?token=SYNTHETIC_ONLY
```

## 只读检查插件状态

在仓库根目录运行对应命令。通过安装包获取插件时，也可运行对应插件目录内的 `scripts/privacy_status.py`。

```bash
python3 scripts/privacy_status.py codex
python3 scripts/privacy_status.py claude --project .
```

检查结果分别列出本地安装记录或缓存版本、配置开关、可见的 Hook 设置和信任记录。Claude Code 可用 `--runtime-version` 传入客户端显示的版本，检查它是否达到文档要求的失败阻断版本。脚本不启动客户端、不修改配置。`hook_execution: not_verified` 表示尚需在新会话中实际验证。输出里的 `expect_pass` 和 `expect_block` 提供两条虚构测试提示词。

## Codex 终端切换方式

在本机终端的仓库目录运行以下命令。注册与 skill 安装相互独立，首次注册默认关闭。

```sh
python3 scripts/codex_privacy.py install  # 注册后先审核 Hooks
python3 scripts/codex_privacy.py status  # 查看设置和注册状态
python3 scripts/codex_privacy.py on      # 脱敏保护
python3 scripts/codex_privacy.py off     # 不脱敏
```

注册后，在桌面端 **Settings → Hooks** 或 CLI 的 `/hooks` 审核并信任两个 `local-privacy-sanitize` Hook。客户端未显示定义时重新打开会话。模式影响同一配置目录下信任并运行这两个 Hook 的本地 Codex 会话。Hook 每次读取当前模式，切换对下一次触发有效。用终端切换，避免把关闭保护交给聊天中的指令。命令中的 `hooks_registered` 仅确认本项目的定义已登记，实际信任状态以 Codex 为准。

| 用户选择 | 行为 |
| --- | --- |
| 脱敏保护（`on`） | `UserPromptSubmit` 在模型请求前检查用户文本，`PostToolUse` 检查受支持的工具结果。命中时阻断。用下方脱敏工具生成副本，在本地复核后重新提交。 |
| 不脱敏（`off`） | 这两个 Hook 直接放行，Codex 按常规流程处理文本和工具结果。 |

Hook 使用同一套检测规则，包括上面的链接检查。可在 Codex 配置目录下的 `local-privacy-sanitize/entities.local.json` 增加本地实体词典，格式见 [配置与安全边界](references/privacy-boundary.md)。默认配置目录是 `~/.codex`，设置了 `CODEX_HOME` 时使用其路径。注册保留已有的其他 Hook 定义，并引用当前仓库中的脚本绝对路径，请保留这个检出位置。关闭时只修改模式文件，其他 Hook 继续执行。

Codex 暂未提供 `UserPromptSubmit` 原地替换提示词的接口。附件、截图、历史上下文、托管工具和未走这两个事件的其他路径需要独立处理。Hook 已启动但检查异常时会返回阻断，Hook 未信任、无法启动或被宿主跳过时需要从客户端核实实际行为。 [OpenAI Hooks 文档](https://learn.chatgpt.com/docs/hooks)

## 先运行虚构示例

```bash
mkdir -p out
python3 scripts/sanitize.py sanitize \
  --input examples/input.example.txt \
  --policy examples/entities.example.json \
  --out-dir out/demo

python3 scripts/sanitize.py check \
  --input out/demo/sanitized.txt \
  --policy examples/entities.example.json
```

`out/demo` 必须不存在。第一次运行返回 `REVIEW_REQUIRED`，并生成 `sanitized.txt`、`report.json`。第二次可能返回 `NO_KNOWN_MATCHES`；两种结果均不代表自动准许上传。文件权限为 0600，输出目录为 0700。再次运行请使用新的输出目录。

示例效果：

```text
输入：陈岚在示例星河公司负责安全，向赵明汇报。小陈负责示例云桥项目。
输出：[PERSON_001]在[ORG_001]负责安全，向[PERSON_002]汇报。[PERSON_001]负责[PROJECT_001]。
```

日期、漏洞数量、修复状态、预算和比例保持原样。它们仍可能是敏感内容，需要按任务需求判断是否允许发送。

## 处理真实材料

1. 在 Agent 无权读取的受控本地位置准备原文，以及姓名、组织、项目等字面实体配置。格式见 [配置与安全边界](references/privacy-boundary.md)。不要把原文或实体值贴入云端聊天。
2. 在本地运行程序，或让 Agent 只使用已知路径执行它，避免原文通过 stdout、搜索命中、附件预览或异常信息进入上下文。
3. 在本地编辑器复核候选：检查漏脱敏、组合身份线索、非公开业务以及过度遮盖。只有明确允许发送的副本才能进入云端工作区。
4. 用实际权限隔离原始数据。不同文件夹和 0600 权限不能隔离以同一 OS 身份运行的 Agent。

程序只输出分类计数，不回显原文、命中片段或本地路径，不保存替换映射。它不自动传输、恢复原文或修改客户端配置。

退出码：`0` 操作完成但仍需复核；`2` 阻断/异常；`3` check 检出已知匹配。解析失败、格式不支持、残留已知匹配、输出目录已存在等情况都不会用原文回退。

## 能力与限制

| 信息 | 处理方式 |
| --- | --- |
| 常见邮箱、大陆手机号、证件形状、部分银行卡号、IP | 内置规则检测与类型占位符 |
| 部分凭据格式、带标签秘密、URL/连接串 | 识别敏感值和不符合放行条件的链接，命中的链接按整体替换 |
| 姓名、公司、地址、项目名 | 本地显式配置；同组别名共享占位符 |
| 未配置姓名、特殊经历、商业秘密、组合再识别 | 不自动判断，必须复核或使用受控环境 |
| PDF、图片、Office、音频 | 未支持，直接输入会被拒绝 |
| Codex 用户文本和受支持的工具返回 | 可选本地检查，命中后阻断并提示脱敏 |
| Claude Code 用户文本、Bash 和受支持的 MCP 返回 | 拦截命中的提示词，替换命中的工具结果 |
| 其他客户端出站流量 | 需要单独的控制措施 |

同一文件内稳定替换，跨文件不进行身份关联。重叠范围合并以避免敏感尾部遗漏。归一化只用于检测，替换范围外的原文不变。原文已发送至云端时，本工具无法撤回这次传输。

Claude Code 的结果替换只发生在工具执行后，已经执行的命令、先前发出的网络请求和在 Hook 前记录的遥测不受影响。Hook 未加载、工具结果格式不受支持、附件、历史上下文和未覆盖的工具路径仍需单独处理。

## 开发与验证

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate_release.py
python3 -m compileall -q -b scripts tests
git diff --check
```

本机有 Codex CLI 时可运行 `python3 tests/codex_smoke.py`。使用支持本地插件的引擎时，可加 `--plugin` 验证原生插件开关对应的配置。测试用临时配置和回环地址模拟模型服务，使用合成样本验证开启及关闭后的实际请求。

测试验证合成样本下的预期行为，不代表真实中文资料达到某个召回率。check 与 sanitizer 共享检测规则，不是独立检测引擎。当前未验证客户端全链路拦截、真实敏感材料、未知格式凭据或通用语义等价。

本地验证结果见 [VALIDATION.md](VALIDATION.md)，完整虚构示例结果见 [output.expected.txt](examples/output.expected.txt)。

本仓库不预设开源许可证；公开可见不等于授予任意再分发授权。需要分发或二次开发时，请与仓库所有者确认许可。
