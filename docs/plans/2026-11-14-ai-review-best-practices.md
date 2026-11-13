# AI 审查最佳实践方案（单审 + 有序兜底）

依据公开文档与现有 `pr-governance/v3` 门控，定稿为：**合并只认一次合格 AI 回执；派发顺序 Codex → Claude → Cursor；不默认双 AI 审，也不默认用 Codex Security Review 挡合并。**

参考：

- [Codex GitHub Code Review](https://learn.chatgpt.com/docs/third-party/github) — `@codex review`；规则写在 `AGENTS.md` 的 `## Code Review Rules`；官方明确审查**不替代** tests / branch protection / required approvals。
- [Codex Security Review](https://learn.chatgpt.com/docs/security/security-review) — `@codex security review`；Pro/Business/Edu/Enterprise；与 Code Review **可能重叠**；面向安全深度分析，不是通用 merge gate。
- [Claude Code Review](https://code.claude.com/docs/en/code-review) / [请求审查](https://code.claude.com/docs/en/code-review-pull-requests) — `@claude review`；仓库可设 Manual / 开 PR / 每次 push；**check 永不失败、永不 approve/block 合并**。
- [Cursor Bugbot](https://cursor.com/docs/bugbot) — 手动触发 `cursor review` 或 `bugbot run`；**bot / GitHub App 发的这两条命令会被忽略**；可开自动审；CI check 默认常为 `neutral`。

## 1. 目标分层

| 层 | 职责 | 强制力 |
| --- | --- | --- |
| A. 确定性 CI | test、Gitleaks、hygiene、actionlint… | required checks |
| B. 单次 AI 审查 | exact-head 回执，无未解决 finding | required `ai-review` |
| C. 风险分级 | R2 需 `owner-approved` / `agent-approved` | required `risk-gate` |
| D. 可选安全加深 | Codex Security Review / 人工 | **不挡合并**（默认） |

OpenAI 与 Anthropic 文档都把自家 AI review 定位为**附加审查员**；硬门禁应继续放在你们已有的 branch protection + `risk-gate`。

## 2. 推荐运行模型

```text
PR head 就绪
  → (可选) 产品侧自动审：仅 Codex 开「开 PR / 跟随个人偏好」即可
  → 10 分钟无回执：nudge 按序请求
       1) @codex review
       2) @claude review
       3) 提示人工发 cursor review / bugbot run（Actions bot 触发无效）
  → risk-gate 取「最新合法 marker」：
       ai-review-receipt:v1 | codex-review-*:v1
       作者须在 reviewers 链上（Codex / Claude / Cursor bot）
  → R2 另需放行标签
  → 合并
```

**判定规则（保持现状语义）**

- 任一配置 reviewer 的**最新**合法回执即可；不要求三家都过。
- 额度满 / 未订阅 → 等下一档或等 ETA；**禁止**静默伪造 success。
- Codex `security_review` 字段：可存在于评论，**不参与** `ai-review` 成败。

## 3. 各产品侧配置（最佳实践）

### Codex（主审）

| 项 | 建议 |
| --- | --- |
| 仓库连接 | QSL / Gdei / Pigbibi 公开业务仓全开 Code Review |
| 自动审 | 优先 **开 PR 时一次** 或跟随个人偏好；避免「每次 push」除非仓很少 |
| 手动 | `@codex review`（与 nudge 一致） |
| Security Review | **默认不开 Auto**；R2 / 资金 / auth / secrets 改动由 owner **按需** `@codex security review` |
| 规则 | 根 `AGENTS.md` 加短小 `## Code Review Rules`（2–3 条仓特有约束）；格式/lint 留给 CI |
| 订阅 | Plus 无 Security Review；Pro+ 才有。退订 Codex 时主审切 Claude |

### Claude（第一兜底）

| 项 | 建议 |
| --- | --- |
| 仓库模式 | **Manual (`@claude review`)**，避免 Codex 已审时再全量自动烧额度 |
| 手动 | `@claude review`；高优先 PR 可用 `@claude review always` |
| Check | `Claude Code Review` **不要**加进 required checks（官方永不 fail） |
| 门控 | 仍靠评论回执 / 适配器 `ai-review-receipt:v1` 点亮你们的 `ai-review` |

### Cursor Bugbot（第二兜底）

| 项 | 建议 |
| --- | --- |
| 自动审 | 可对核心仓开 Bugbot 自动审，作**静默产能**；不替代 Codex 主路径 |
| 手动 | 人类发 `cursor review` 或 `bugbot run`（**不要依赖 Actions bot nudge**） |
| Check | `Cursor Bugbot` 可不进 required；合并仍认 `ai-review` |
| 规则 | 可选 `BUGBOT.md`；与 `AGENTS.md` Code Review Rules 对齐「仓特有危险」 |

## 4. 与你们门控的接线

| 机制 | 做法 |
| --- | --- |
| `policy.default.json` | `reviewers`: Codex → Claude → Cursor；`dispatch_mentions` 同步 |
| `GOVERNANCE_REVIEWERS_JSON` | 组织变量覆盖身份，不改代码 |
| nudge | 同时请求 Codex + Claude；Cursor 用「请人工触发」说明 |
| Pigbibi 公开仓 | required 补齐 `ai-review` |
| 私有仓 | `merge_gate.py` 同 marker 集；仍不买 Pro |
| 中枢仓 | `GdeiAssistant/.github`、`PrGovernance` 抬到与业务仓同等保护 |

## 5. 明确不做的事

1. **不**要求 Claude + Codex 双过才合并。  
2. **不**把 Codex Security Review 设为 required（与 Code Review 重叠、额度另算、Plus 不可用）。  
3. **不**把 Claude / Bugbot 的产品 check 当作唯一 merge 约束（Claude 永不 fail；Bugbot 默认常 neutral）。  
4. **不**在额度用尽时降级「免审合并」。

## 6. 推广顺序

1. 合并 `pr-governance` 多 provider 改动 → 固定 `__GOVERNANCE_SHA__`。  
2. 设 `GOVERNANCE_REVIEWERS_JSON`（见 `reviewers.example.json`）。  
3. 产品控制台：Codex 主审；Claude Manual；Bugbot 按需自动。  
4. 同步 workflow pin → 补 Pigbibi `ai-review` → 私有仓 merge_gate。  
5. 抽 1–2 个 QSL 仓试点 nudge + 回执，再 org 级铺开。

## 7. 验收标准

- 普通 PR：`@codex review` 后 `ai-review` 变绿即可合（其它 required 也绿）。  
- Codex 不可用：Claude 合法回执同样点亮 `ai-review`。  
- Cursor：人工 `cursor review` / 自动 Bugbot 产出合法回执后可过。  
- R2：无放行标签则 `risk-gate` 红。  
- Security Review：可选加深，缺失不单独失败。
