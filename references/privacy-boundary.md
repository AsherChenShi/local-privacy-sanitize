# 配置与安全边界

## 本地实体配置

```json
{
  "entities": [
    {"type": "PERSON", "values": ["虚构姓名甲", "虚构别名甲"]},
    {"type": "PERSON", "values": ["虚构姓名乙"]},
    {"type": "ORG", "values": ["示例企业"]}
  ]
}
```

每组表示一个实体，`values` 是该实体的全部字面别名，同组共享占位符。类型只支持 PERSON、ORG、LOCATION、PROJECT、ACCOUNT、SENSITIVE。每个值为 2–200 字符；匹配区分大小写，不使用正则。配置最多 200 组，每组 20 个别名，文件最多 256 KiB。归一化后重复的别名、未知字段、重复 JSON 键会被拒绝。真实配置留在本地私有目录，切勿上传 GitHub 或交给云端模型编写。

## 检测范围

内置规则涵盖常见 ASCII 邮箱、中国大陆手机号（部分空格、横线、+86 变体）、18 位身份证形状（不以校验码过滤）、美国 SSN 形状、部分 Luhn 银行卡号、IPv4/IPv6，以及带标签的账号。URL/连接串命中规则时按整体替换。当前识别 http(s)、ftp、sftp、ssh、postgres(ql)、mysql、mongodb、redis、amqp(s) 等方案。

凭据规则识别部分 API token 前缀、JWT 形状、Bearer、常见中英文凭据标签，以及部分 PEM 私钥。引号包围的标签值整体替换，包括其中的空格；检测到不完整的私钥或带引号凭据会阻断。**这些是启发式规则，不是完整凭据检测器。** 未识别的提供商格式、其他语言、分行或编码后的秘密仍可能遗漏。

JSON 结果中的明确凭据字段结合字段名和值检查。文件工具会在复检时拒绝含有残留凭据的候选。Claude Code 对无法检查且结果结构已知的 MCP 结果返回替代内容。提示词拦截说明使用固定类别，宿主支持时请求隐藏被拦截的原文。宿主自己的历史记录仍需独立管理。[Claude Code 拦截反馈](https://code.claude.com/docs/en/hooks#what-a-blocked-prompt-leaves-behind)

检测视图处理全角 ASCII 与部分零宽字符，匹配结果映射回原始文本，只替换相应范围。不要将其解释为全面 Unicode 混淆防护。双向控制符、NUL 等不支持的控制字符会阻断。过多匹配会阻断，以限制资源消耗。

嵌套匹配取覆盖整个范围的规则；部分重叠取并集，使用 SENSITIVE 占位符，避免保留敏感范围的尾部。合并可能减少实体分类精度，须结合本地复核判断语义是否足够。

## 结构化预检

预检按文件后缀选择文本、JSON 或 Markdown。`.txt` 和 `.log` 可以用 `--format json` 或 `--format markdown` 明确指定结构化内容。候选文件使用对应后缀，按同一格式复检。

JSON 只替换命中的字符串值。对象键、数组顺序、层级、未命中的值及其原始数字写法会保留。重复键、非法语法、敏感键名或命中后无法安全保留类型的值会阻断。业务字段 `type` 的普通字符串由 JSON 格式规则处理。

Markdown 支持常见行内链接、表格和代码围栏。扫描时按可识别结构限制替换范围，保留周围语法。带 `json` 标记的围栏复用 JSON 预检。超出受支持范围的内容须在本地复核。解析失败、输出结构校验失败或仍有已知匹配时，程序拒绝生成候选。[JSON 规范](https://www.rfc-editor.org/rfc/rfc8259) · [GFM 规范](https://github.github.com/gfm/)

## 本地预览和敏感级别

在 `sanitize` 上使用 `--preview` 会在私有输出目录内生成权限为 `0600` 的 `review.html`。替换列表使用实际编辑在原文中的位置，疑点使用候选中的位置。页面只保存定位、类别、占位符、疑点原因等元数据，以及用于校验候选的 SHA-256。原文、候选正文和本机路径不写入预览。只有用户明确选择同一批次的候选时，页面才在浏览器本地读取该文件并显示所选位置附近的内容。疑点相关的内容默认遮盖。文件哈希不符时请重新生成预览。页面无需外部资源或网络服务。

待核对只提示有限的可定位线索，例如「客户姓名」「收货地址」和「内部项目」字段仍有未遮盖的值。按配置保留的字段如果有明确标签，也可能成为疑点。结合任务和材料范围判断是否发送。替换位置和类别本身也可能敏感，预览和候选一起留在本地。页面不记录审批结果，`REVIEW_REQUIRED` 的含义不变。

独立预检中的高敏类型包括命中的凭据、证件号码、支付卡、账号、邮箱、电话、IP、敏感链接，以及词典中标为 `SENSITIVE` 的实体。能安全替换时直接替换。遇到无法安全处理的结构时，程序拒绝生成候选。可由用户配置的普通敏感类型是实体词典中的 `PERSON`、`ORG`、`LOCATION`、`PROJECT`，默认全选替换。这是工具的操作分级。按业务或组合信息判断需要始终处理的姓名、地点等，可以在本地词典中直接标为 `SENSITIVE`。

将要替换的普通类型名称写入 `~/.config/local-privacy-sanitize/review-policy.local.json`。

```json
{"ordinary_types":["PERSON","ORG","LOCATION","PROJECT"]}
```

本地预检与两端启用的 Hook 默认读取这份配置。文件缺失时采用以上四种类型。省略某种类型会保留仅按该类型命中的值，与高敏规则重叠的部分仍按高敏处理。未知类型或格式错误会让本地命令停止，Hook 则回退为处理全部类型。显式传入的 `--review-policy PATH` 只覆盖本地命令。用同一配置生成并复检候选。页面筛选只影响当前显示的条目。

## 链接检查规则

文件脱敏、复检和两个宿主的 Hook 都按同一套 URL 规则做本地判断。符合主机、路径和查询限制的 HTTPS 链接可跳过 URL 匹配。

| 主机 | 路径和查询限制 |
| --- | --- |
| `github.com`、`api.github.com` | 常见账号或仓库页、限定仓库资源和 API 路径。API 响应中的部分 `{/sha}` 形式 URI 模板也可通过。查询只接受符合格式的 `head_sha`、`page`、`per_page`、`plain`、`sha`、`tab` |
| `raw.githubusercontent.com`、`avatars.githubusercontent.com` | 原始文件路径不带查询。头像仅限数字用户 ID 和可选的数字 `v` 参数 |
| 明确列出的文档主机 | 必须符合对应文档路径前缀。查询只接受 `api-version`、`lang`、`locale`、`site_variant`、`surface`、`translationFallback`、`trk`、`version`、`view` 及符合格式的值 |

文档来源包括 GitHub Docs，OpenAI 的 Learn、Developers、Platform 和 Help，Claude Code、Anthropic Docs 和 Claude Platform，以及 Python、MDN、Microsoft Learn、OWASP、NIST、Presidio 的指定文档路径。完整主机、路径和参数限制以 [检测代码](../scripts/sanitize.py) 为准。

带用户信息、端口、访问令牌、签名、未知或重复查询、重定向参数的链接仍按敏感链接处理。HTTP、连接串、内网链接和不明确的形式仍会命中。查询参数限制只用于过滤文本 URL，同时应由用户决定和授权实际发送的请求。

链接放行后，凭据、邮箱、IP 或本地实体词典等规则仍独立检查 URL 与周围文字。检查不联网，不跟随跳转，也不能凭 URL 外观判断仓库是否公开。提交私有仓库链接之前仍需由用户判断适合发送哪些信息，尤其是仓库名、分支名和文件路径。

在符合放行条件的 GitHub Actions 运行页面或对应 API 路径中，只有恰好覆盖运行编号全部字符的手机号命中才跳过。正文中的号码和本地实体词典规则仍照常检查。允许的主机也会在链接编码解码后检查已知凭据和部分个人信息。

## 保留与缺失

程序保留替换范围外的原文，包括角色关系、日期、数值、否定和不确定表达。精确日期、金额、诊断、独特经历本身也可能敏感；保留它们不代表允许外发。可通过显式实体值遮盖不必要的信息，或在本地计算任务所需的汇总结果。程序不会自动进行日期泛化、噪声添加或统计匿名化。

没有内置姓名/地址 NER、OCR、语音识别、PDF/Office 解析、通用国际手机号检测、业务分类器、跨文档实体解析、组合再识别判断、密钥保险库或映射恢复功能。哈希用于候选完整性核对，不用来替代实体匿名化。脱敏不是不可逆匿名化，也不代表满足任何特定法律要求。

## 信任边界

假设操作系统、本地 Python、skill 源码和选定的父目录可信。拒绝输入文件的末端符号链接、非普通文件以及已存在的输出目录；这不是对全部祖先目录的符号链接检查，也不是抵抗恶意本地同账户进程的完整沙箱。0700/0600 权限不能阻止以同一 OS 身份运行的 Agent 读取原文或候选。

原文、策略、候选和报告都应留在受控本地存储。只产生内存中的临时替换表，不保存映射；这不保证进程内存、交换文件或系统备份不会保留原始数据。程序不使用网络、第三方模型或遥测，但不管理宿主应用及操作系统的网络行为。

skill 只提供工作流。用户输入、历史聊天、Memory、连接器、工具输出、文件名、附件和截图，都可能存在独立上传路径。必须另行通过客户端能力或实际隔离来约束；不可因安装 skill 就宣称“所有大模型请求已拦截”。程序没有自动批准、自动上传或自动回填原文功能。

## Codex 可选检查

仓库的 `scripts/codex_privacy.py` 提供 `install`、`status`、`on` 和 `off`。在本机终端运行。首次注册默认关闭，用户在 Codex 的 Hooks 设置中审核并信任定义，再按需开启。开启时本地检查提示词和支持的工具结果，命中后阻断。需脱敏时用文件工具生成副本，复核后再发送。Hook 本身只输出固定反馈，提示词和工具结果不会被该脚本记录到文件。

这两个 Hook 覆盖 Codex 实际调用的 `UserPromptSubmit` 和 `PostToolUse` 事件。它们无法替代附件、历史上下文、托管工具的独立控制。工具执行后的阻断不能撤销已经发生的外部操作。模式开关由本机用户维护，具备同等读写权限的进程也能修改这些设置。

## Hook 运行失败

两个插件保留宿主侧 10 秒上限。监督进程启动后，把扫描交给独立进程并限制为 6 秒。超时、扫描进程异常退出或返回不合规结果时，按对应事件返回固定反馈。插件不把原文放入进程参数、检查日志或拦截理由中。

宿主没有运行监督进程时，插件无法返回阻断决定。Codex 未信任、已停用或被宿主先终止的 Hook 可能无法阻止原生发送。此时应按未受保护处理。先在本机生成、复检并人工审阅候选副本，再提交。Claude Code 在支持的版本上可通过 `onFailure: "block"` 拦截已配置的提交前检查失效。工具执行后的结果替换需要宿主接受与原结果匹配的结构。[Codex Hook 信任](https://learn.chatgpt.com/docs/hooks#review-and-trust-hooks) · [Claude Code 故障处理](https://code.claude.com/docs/en/hooks#block-the-action-when-a-hook-fails) · [Claude Code 结果替换](https://code.claude.com/docs/en/hooks#posttooluse-decision-control)

## Claude Code 内置 Read 保护

要在读取前拒绝内置 `Read` 打开指定目录内的文件，在 `~/.claude/local-privacy-sanitize/protected_read_roots.local.json` 保存目录清单。设置 `CLAUDE_CONFIG_DIR` 时，使用该目录下的相同相对路径。

```json
{"roots":["/absolute/path/to/private-material"]}
```

目录必须为绝对路径。检查会比较原始路径和解析符号链接后的路径。没有清单时，插件不新增目录拒绝规则。工具结果中的文本继续按 `PostToolUse` 检查。Bash、其他文件工具和并行程序需要各自的访问限制。[Claude Code 执行前检查](https://code.claude.com/docs/en/hooks#pretooluse-decision-control)

## 报告解释

- `REVIEW_REQUIRED`：候选生成且共享规则复检通过，仍需本地复核。
- `NO_KNOWN_MATCHES`：check 未命中当前配置启用的规则，仍需本地复核。
- `KNOWN_MATCHES_FOUND`：check 命中，退出 3；不回显命中值。
- `BLOCKED`：无法完成检查或处理，退出 2；不得使用原文回退。
- 分类计数是被替换的出现次数和不同占位符数量，不是召回率。
- `output_sha256` 仅绑定候选文本，候选修改后原报告失效；它不是审批、数字签名或脱敏完整性证明。

## 设计参考

- [OpenAI：Skills](https://learn.chatgpt.com/docs/build-skills)：技能是可复用工作流。
- [OWASP：Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/)：输入清理、访问控制与提示词约束的局限。
- [Presidio 官方说明](https://presidio.dataprivacystack.org/)：自动检测不能保证发现全部敏感信息。本项目没有依赖或集成 Presidio。
- [NIST SP 800-188](https://csrc.nist.gov/pubs/sp/800/188/final)：去标识化、准标识符与再识别风险。
