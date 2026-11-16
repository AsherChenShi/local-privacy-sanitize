---
name: local-privacy-sanitize
description: 使用离线本地程序为 UTF-8 文本生成敏感信息脱敏候选副本，保留实体关系和任务事实。适用于上传前处理文件、检查脱敏结果；不提供客户端全流量拦截，也不将原文发送给云端模型脱敏。
---

# 本地隐私脱敏

为用户准备可在本地复核的脱敏候选文件。此 skill 的程序只使用 Python 标准库，不调用网络或外部模型。

## 使用边界

- 云端 Agent 不应读取原文、实体配置或映射表，也不应先把原文打印到工具结果再脱敏。只接收用户指定的本地路径，直接运行脚本；避免 `cat`、搜索命中片段、原文 diff、错误回显及附件预览进入上下文。
- 如果原文已粘贴到云端聊天，明确说明本次传输已经发生；后续脱敏无法撤回该传输。
- 原文及实体配置需要有实际的读取权限隔离。此 skill 本身不创建隔离环境、不修改客户端 hook，也不能阻止其他工具绕过它读取原文。
- 支持 macOS/Linux、Python 3.9+、不超过 2 MiB 的 UTF-8 `.txt`、`.md`、`.log`。其他格式先在可信本地环境转换并检查；不要将 PDF、图片、音频、Office 附件当成已支持。
- 人名、组织、地址、内部项目名须在本地 JSON 中配置；没有通用 NER、上下文隐私判断或自动匿名化能力。即使未检出，也不能宣布“无敏感信息”。

## 操作

将下面的 `/path/to/local-privacy-sanitize` 替换为本 SKILL.md 所在目录的绝对路径；输入、策略及输出路径由用户指定。不要把原文或真实实体值放进命令参数、环境变量或聊天。省略 `--policy` 时只有结构化规则覆盖。

```bash
python3 /path/to/local-privacy-sanitize/scripts/sanitize.py sanitize \
  --input /private-source/input.txt \
  --policy /private-config/entities.local.json \
  --out-dir /local-review/new-candidate
```

输出目录必须不存在，父目录必须已存在。程序生成权限为 0600 的 `sanitized.txt`、`report.json`；目录权限为 0700。stdout 只包含固定状态和分类计数，不包含原文、文件内容、路径或映射。

程序会规范化检测视图、合并重叠敏感范围、进行残留规则检查，并在同一文件内稳定替换实体。同组别名共享占位符；不同调用的占位符不能用来关联身份。替换范围以外的文字保持原样，包括日期、金额、否定词和原有标点。

## 复核和使用

1. 从 stdout 获取摘要即可，不自动读取候选文件。`REVIEW_REQUIRED` 表示生成候选成功，**不表示准许上传**。
2. 提示用户在本地编辑器核对候选内容：遗漏身份线索、非公开业务、上下文组合识别、任务不需要的敏感事实，以及过度遮盖造成的意义变化。不要自动为用户确认复核。
3. 用户明确确认某个候选可发送后，才在其授权范围内读取该副本。修改候选后需要重新检查并本地复核；报告中的 SHA-256 只绑定生成时的候选，不是签名或审批凭证。
4. 可运行以下命令检查已知规则残留。检查器与脱敏器共享规则，不能证明没有未知类型信息，也不能替代本地复核。

```bash
python3 /path/to/local-privacy-sanitize/scripts/sanitize.py check \
  --input /local-review/new-candidate/sanitized.txt \
  --policy /private-config/entities.local.json
```

退出码：`0` 为操作完成（仍需复核），`2` 为阻断或异常，`3` 为 check 检出已知匹配。任何非零退出都停止本次候选使用，修复后生成新的候选目录；不要以原文回退。

对于必须保留敏感原文才能完成的任务，选择符合要求的本地或受控处理环境。不要擅自改写金额、日期、事实或否定关系来“通过检查”。

需要配置格式、完整能力范围和威胁边界时，读取 [privacy-boundary.md](references/privacy-boundary.md)。
