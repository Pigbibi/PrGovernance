# Grok Bot 任务卡：三产品审查模式配置

Owner 授权：按「单审 + Codex → Claude → Cursor 兜底」配置三家产品侧。  
**不要**开默认双 AI 审；**不要**把 Security Review / Claude check / Bugbot check 设成合并必需。  
不升级 GitHub Pro。

## A. Codex（主审）

控制台：ChatGPT / Codex → Settings → Code Review（仓库级）

对下列范围逐仓或按 org 批量（能批量就批量）：

- **QuantStrategyLab**：全部活跃公开业务仓（含 `.github`）
- **GdeiAssistant**：全部活跃公开仓（含 `.github`）
- **Pigbibi**：全部活跃公开仓（含 `PrGovernance`）

| 项 | 设为 |
| --- | --- |
| Code Review / Automatic review | **开** |
| 自动审范围 | **All PRs**（或等价「仓库内全部 PR」） |
| Review trigger（自动） | **On PR open**（开 PR / ready 时一次）。不要用「每次 push」，除非仓极少 |
| Personal preferences Automatic review | 与仓库策略一致即可；以仓库设置为准 |
| **Auto security review** | **关**（默认） |
| Security Review 触发 | 仅人工：`@codex security review`（R2 / 资金 / auth / secrets 由 owner 按需点） |
| 仓库连接 | 确认 GitHub App `chatgpt-codex-connector` 已装且有上述仓权限 |

验收：任意试点 PR 评论 `@codex review` 后出现 👀 与审查评论；回执含 `codex-review-state:v1` 或等价 marker。

## B. Claude Code Review（第一兜底）

控制台：claude.ai → Admin → Claude Code → Code review

| 项 | 设为 |
| --- | --- |
| Allow code review | **开** |
| GitHub App `claude` | 已安装；覆盖与 Codex 相同的三主体仓库集合 |
| **每个仓库的 when reviews run** | **Manual (`@claude review`)** |
| Review level / thoroughness | 保持默认或现有档；不要为兜底特意拉到最高 |
| 不要 | 不要设成 After every push（会与 Codex 双烧额度） |

验收：试点 PR 在 Manual 下不会自动出 `Claude Code Review`；评论 `@claude review` 后出现 check + 评论。

## C. Cursor Bugbot（第二兜底）

控制台：Cursor Dashboard → Integrations / Automations → Bugbot

| 项 | 设为 |
| --- | --- |
| GitHub 连接 | 已连接；App `cursor` 覆盖上述仓库集合 |
| Bugbot 仓库开关 | **核心仓可开自动审**（建议：QSL 平台仓 + Gdei 主仓 + Pigbibi 高活仓）；其余可先关、靠人工 |
| 手动触发 | 人类评论：`cursor review` 或 `bugbot run` |
| 重要限制 | **Bot / GitHub App 发的 `cursor review` / `bugbot run` 会被忽略**；不要指望 Actions nudge 代触发 |
| Fail check on findings | **关**（或保持不把 `Cursor Bugbot` 加进 GitHub required checks） |
| 规则 | 可选后续补 `BUGBOT.md`；本次可不做 |

验收：人工发 `cursor review` 后出现 Bugbot 评论；或已开自动审的仓在 push 后出现审查。

## D. 组织变量（GitHub，门控用）

在 **QuantStrategyLab**、**GdeiAssistant** 组织，以及 **Pigbibi** 用户/相关仓，设置 Actions variable：

- 名：`GOVERNANCE_REVIEWERS_JSON`
- 值：见 `pr-governance/reviewers.example.json`（一行压缩 JSON 也可）

已有 `RISK_GATE_OWNER` / `RISK_GATE_OWNER_ID` 保持不变。

内容（与 example 一致）：

```json
[{"provider":"codex","app_id":1144995,"user_id":199175422,"login":"chatgpt-codex-connector[bot]"},{"provider":"claude","app_id":1236702,"user_id":209825114,"login":"claude[bot]"},{"provider":"cursor","app_id":1210556,"user_id":206951365,"login":"cursor[bot]"}]
```

## E. 明确不要做

1. 不要要求 Claude + Codex 都过才合并  
2. 不要开 Codex Auto security review 作为默认  
3. 不要把 `Claude Code Review` / `Cursor Bugbot` 加进 branch protection required contexts  
4. 不要改 merge 标准去「额度满就免审」  
5. 不要升级 GitHub Pro（本次）

## F. 回报格式（给 Owner）

完成后在进度里写：

| 主体 | Codex 仓数/模式 | Claude 仓数/Manual | Bugbot 开自动的仓 | GOVERNANCE_REVIEWERS_JSON |
| --- | --- | --- | --- | --- |
| QuantStrategyLab | | | | |
| GdeiAssistant | | | | |
| Pigbibi | | | | |

卡点（未装 App、无权限、Plus 无 Security 等）单独列。
