# 评测 harness（P1-4）

离线、只读的评测工具：把一次真实任务运行折算成可比较的指标，用于回答
“这次改动/换模型/换预算，是变好了还是退步了”。

它**不启动靶场、不重跑 agent、不发网络请求**。靶场由你按场景 manifest 的
`setup` 启动，任务照常在 Web/API 里创建并跑完；评分只读 PostgreSQL 里已经
落库的结果。

## 快速开始

```bash
# 1) 启动靶场（以 DVWA 为例）
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# 2) 在破军里创建任务：目标填 http://127.0.0.1，目标描述写清要拿到的证据
#    等任务跑完/暂停后，记下 task id（例如 18）

# 3) 校验场景库
pojun-maint bench validate

# 4) 给这次运行打分
pojun-maint bench score \
  --config /opt/pojun/config.json \
  --scenario dvwa-sqli-xss \
  --task 18 \
  --out /tmp/run-18.json

# 5) 改代码/换模型后重跑同一场景，再对比
pojun-maint bench compare --a /tmp/run-18.json --b /tmp/run-42.json \
  --out /tmp/diff.json --markdown /tmp/diff.md
```

`compare` 在 PASS→FAIL（退步）时退出码为 1，可直接接 CI/脚本。

## 指标定义

| 字段 | 含义 |
|---|---|
| `pass` | 所有**必得项**命中且证据达标；`require_goal=true` 时还要求所有 goal 都 met；预算超限会强制 fail |
| `required_found / required_total` | 必得项命中数（`optional=true` 的预期项不参与 pass） |
| `expected_found` | 含 optional 的预期项命中数 |
| `evidence_completeness` | 命中项中 `evidence` 长度 ≥ `min_evidence_runes`（默认 120，`-1` 关闭）的占比 |
| `unexpected / extra_rate` | 未被任何预期项匹配的 finding。**没有人工复核时只能叫 unexpected，不直接叫误报**；`extra_rate = unexpected / findings_total` |
| `stages_seen / stage_total` | 场景声明的维度（recon/authz/injection/upload/rce/...）是否在 `intent_reflections.dimension` 中出现 |
| `tokens_input / tokens_output` | `llm_usage` 全量（含 planner/worker/压缩/报告），input 含 cache read/write |
| `cost_usd / cost_known` | 按 `pricing` 包内置参考价逐模型估算；有模型不在表里时 `cost_known=false`，USD 上限不强制执行 |
| `duration_minutes` | `first_run_at`（无则 created_at）→ `completed_at`（无则 now） |
| `artifacts` | `task_artifacts` 证据附件数 |

匹配规则：`vulnclass` 先经 `db.NormalizeVulnClass` 归一后精确匹配；`asset` 是
finding 关联资产 URL/domain/ip 的子串（不区分大小写）；`severity` 非空时要求
精确匹配。每条 finding 最多匹配一条预期项。

## 场景 manifest

```json
{
  "id": "vulhub-log4j2-cve-2021-44228",
  "name": "Log4j2 JNDI RCE",
  "source": "vulhub",
  "setup": "cd vulhub/log4j/CVE-2021-44228 && docker compose up -d",
  "target": "http://127.0.0.1:8983",
  "goal": "触发 Log4j2 JNDI 注入并取得命令执行/回连证据",
  "stages": ["recon", "injection", "rce"],
  "require_goal": false,
  "max_minutes": 45,
  "max_usd": 2.0,
  "expected": [
    {"vulnclass": "RCE", "severity": "critical"},
    {"vulnclass": "注入", "optional": true}
  ]
}
```

- `id` 在场景库内唯一；`name/goal/expected` 必填。
- `expected[].optional=true` 是加分项，不影响 pass。
- `expected[].min_evidence_runes` 默认 120；`-1` 关闭证据长度检查。
- `max_minutes/max_usd` 是预算硬线；超出会强制 fail，并在 `budget_notes` 说明。
- `target/setup/notes` 仅元数据，评分不使用。

## 内置场景（20 个）

| 类别 | 场景 |
|---|---|
| 综合靶场 | DVWA、Juice Shop、WebGoat、bWAPP |
| Java 生态 | Log4j2、Fastjson 1.2.47、Shiro、Struts2 S2-045、WebLogic、Confluence、Jenkins、ActiveMQ |
| PHP/其他 | ThinkPHP 5.0.23、GitLab |
| 基础设施 | Redis、MongoDB、Elasticsearch、Docker API、Kubernetes API、Zabbix |

场景 manifest 用 `--scenario <id>` 直接引用内置场景；也可以传仓库/磁盘上的
`.json` 文件或目录（`--scenario eval/scenarios`）。内置场景通过 `go:embed`
随二进制分发，部署机上不需要额外上传 `eval/scenarios`。

Vulhub 场景的 `setup` 是路径约定，实际端口以 `docker compose ps` 为准；不同
Vulhub 版本目录可能变化，跑之前先用 `--scenario` 校验并核对 `setup`。

## 方法学

- **固定模型/预算/重试**：同一组对比必须使用相同 LLM profile、`task_budget_*`、
  重试策略；否则差异无法归因。
- **pass@1**：一次运行一个 `RunResult`，`pass` 即 pass@1。多次运行分别落盘，
  人工按 `pass` 统计 pass@k；不要把同一次运行拆成多次。
- **A/B 回归**：`compare` 输出指标 delta、`newly_missing/newly_found`；退步时
  退出码 1。
- **先看证据再看分数**：`evidence_completeness` 低但 pass=true 通常说明场景的
  `min_evidence_runes` 设低了；不要为了让分数好看调低阈值。

## 已知边界

- `unexpected` 不是严格误报：一个任务可能合法地发现场景没列出的漏洞。需要人工
  复核时把它当“待归类”，不要直接计入 FP。
- 阶段覆盖依赖 `intent_reflections`（v0.4.100 起每个终态意图都会写）；更老的
  任务没有 reflection 时 `stages_seen=0`，不代表没测。
- 成本是参考价估算，不承诺账单精度；未知模型不会静默算成免费（`cost_known=false`）。
- 评分不检查“漏洞是否真实可利用”，那由 `audit_finding` / 人工复核负责；harness
  只检查“有没有按预期类别与证据形态落库”。
