# local-privacy-sanitize

一个用于 Codex、Claude Code 等支持 `SKILL.md` 的 Agent 的本地脱敏 skill。使用 Python 标准库为文本生成**待本地复核**的副本，保留实体关系与关键事实。程序不调用网络或外部模型。

**这是脱敏候选生成器，不是客户端上传拦截器。** 安装 skill 不会自动拦住聊天输入、工具返回、Memory 或附件上传。未配置的人名、商业秘密和组合身份线索仍可能保留。

支持 macOS/Linux、Python 3.9+、UTF-8 `.txt` / `.md` / `.log`，单文件不超过 2 MiB。所有仓库示例和测试数据均为虚构，不来自真实用户资料。

## 安装

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
| 部分凭据格式、带标签秘密、URL/连接串 | 识别后替换，URL 按整体替换 |
| 姓名、公司、地址、项目名 | 本地显式配置；同组别名共享占位符 |
| 未配置姓名、特殊经历、商业秘密、组合再识别 | 不自动判断，必须复核或使用受控环境 |
| PDF、图片、Office、音频 | 未支持，直接输入会被拒绝 |
| 客户端全部出站流量 | 未拦截，需要另行部署控制 |

同一文件内稳定替换，跨文件不进行身份关联。重叠范围合并以避免敏感尾部遗漏。归一化只用于检测，替换范围外的原文不变。原文已发送至云端时，本工具无法撤回这次传输。

## 开发与验证

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate_release.py
python3 -m compileall -q -b scripts tests
git diff --check
```

测试验证合成样本下的预期行为，不代表真实中文资料达到某个召回率。check 与 sanitizer 共享检测规则，不是独立检测引擎。当前未验证客户端全链路拦截、真实敏感材料、未知格式凭据或通用语义等价。

本地验证结果见 [VALIDATION.md](VALIDATION.md)，完整虚构示例结果见 [output.expected.txt](examples/output.expected.txt)。

本仓库不预设开源许可证；公开可见不等于授予任意再分发授权。需要分发或二次开发时，请与仓库所有者确认许可。
