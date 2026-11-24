# Agent 工程模式调研：对 Go 长任务渗透编排器的取舍（2025-2026）

> 调研日期：2026-11-24。证据分级：强=公开基准/受控实验/可复现；中=厂商内部评测或大规模生产 telemetry；弱=单一案例/预印本/厂商宣传。

---

## 结论摘要

1. **长任务瓶颈已从“模型会不会做”转向“harness 能否维持状态、控制上下文、及时收尾”**。同一模型换 harness，SWE-bench Verified 解出率可差 44 个百分点，每解一题 token 可差 20 倍以上；Terminal-Bench 中 50% 以上失败是超时而非不会做。
2. **多 Agent 的正确用法是“只读并行 + 写入单线程”**。Anthropic 研究型多 Agent 内部评测比单 Agent 高 90.2%，但代价 15 倍 token；Cognition 2026 复盘收敛为：并行 agent 只贡献情报，写操作保持单线程。
3. **上下文管理性价比排序：稳定前缀缓存 > 工具结果可逆压缩 > 摘要 > 专用记忆服务**。Anthropic 生产 agent 输入中位数 84% 来自缓存；不用缓存时 SWE-bench Pro 成本 3.3 倍。专用记忆系统公开基准互相矛盾，收益远不如“文件系统 + SQL + 好的检索工具”。
4. **渗透领域公开证据支持“阶段化 + 人工辅助”**。AutoPenBench 全自主 21%，人类辅助 64%；PentestEval 端到端 31%，PentestGPT 39%；CVE-Bench 最佳 agent 仅利用 13%。把长任务拆成可验证阶段，比追求端到端 autonomy 更实际。
5. **对 Go 编排器最值得吸收的是运行时纪律，而不是某个 Python 框架**：事件日志/检查点、幂等副作用、显式预算、类型化终止原因、证据账本、OTel span 树。ADK Go 2.0（2026-06 GA）是唯一成熟的 Go 原生图/HITL 运行时，可参考或依赖。

---

## 1. 模式清单

### 1.1 编排与规划

| 模式 | 代表 | 证据 | 代价 | Go 适配 | 优先级 |
|---|---|---|---|---|---|
| 单线程线性 agent + 压缩 | Cognition、Claude Code、Codex | Cognition 两原则：共享完整 trace、动作携带隐式决策；2026 仍主张写入单线程。中 | 上下文增长，需压缩器；并行度低 | 很适合：单 goroutine 状态机 + ctx 取消 | P0 |
| Planner-Executor + 滚动重规划 | Manus planner agent；Magentic-One Task/Progress Ledger；Codex Plan.md | Manus todo.md 曾占 1/3 动作，改 planner agent 后省 token 且有外部视角；无进展时重写 ledger。中 | 每轮多一次规划；计划抖动 | 很适合：planner 无状态函数，计划版本化落库 | P0 |
| Supervisor + 隔离子 agent | Claude Code subagents（5 层）、Anthropic 多 Agent、OpenAI Agent.as_tool | 3-5 并行子 agent，返回 1-2k token 摘要，研究任务高 90.2%，总 token 15 倍；子 agent 描述>15k token 告警。中 | 同步阻塞；重复上下文 | 很适合：goroutine + channel，每 worker 独立预算 | P0 |
| 图/DAG + 人工闸门 | LangGraph 1.0；ADK Go 2.0 | LangGraph 每 super-step checkpoint，pending writes 恢复不重跑；ADK Go 2.0 节点级 retry/timeout、durable HITL。强/中 | 框架抽象成本；图膨胀 | 很适合：ADK Go 2.0 已 GA，或自研 DAG + 事件日志 | P1 |
| 对等 agent 团队 | Claude Code agent teams（实验）；A2A 1.0 | token 显著更高、恢复/关闭有限制。弱 | 协调复杂、一致性差 | 中等 | P2 |
| Actor/Crew | AutoGen v0.4；CrewAI | CrewAI 建议确定性放 Flows，Crews 只做自治单元。中 | 运维复杂、角色扮演可控性差 | 中等，框架增益低 | P2 |

### 1.2 上下文、记忆、技能

| 模式 | 代表 | 证据 | 代价 | Go 适配 | 优先级 |
|---|---|---|---|---|---|
| 稳定前缀 + append-only | Manus、Claude Code、Anthropic caching | Manus 输入/输出约 100:1，缓存读 0.3 vs 未缓存 3 美元/MTok；Anthropic 中位 84% 缓存，前 10% 94%；无缓存 SWE-bench Pro 成本 3.3 倍。强 | 前缀改动击穿缓存；序列化必须确定性 | 很适合：固定 struct 字段序、禁 map 序列化、记录 prefix hash | P0 |
| 两段式压缩：可逆 compaction → summarization | Manus、Claude Code、Codex /responses/compact | Manus 工具结果 full/compact 双格式，compact 只留 path/URL；先压最老 50%，保留最近 3-5 对；Anthropic context editing 100 轮 token 降 84%、agentic search +29%（memory tool +39%）。中 | 实现复杂；摘要不可逆 | 很适合：工具结果落 artifact store，上下文只放 handle | P0 |
| 工具结果清理/context editing | Anthropic clear_tool_uses、Claude Code | 默认 100k input 触发、保留最近 3 对；clear_at_least 防白破缓存；exclude_tools 保护证据。中 | 删早丢观测 | 很适合：evidence 落盘后按阈值清理 | P0 |
| 结构化笔记 + 文件系统即记忆 | Manus todo.md、Claude Code TodoWrite、Anthropic progress.txt、Letta Filesystem | Anthropic 长任务：200+ 功能 JSON 只允许改 passes；每 session 先读 progress、git log、跑 init.sh。Letta 文件系统 agent LoCoMo 74.0%，高于 Mem0 报告 68.5%。中 | 文件腐烂，需 schema/GC | 很适合：SQLite/Postgres + workspace 文件 | P0 |
| 专用记忆服务/睡眠计算 | MemGPT/Letta、mem0、Zep/Graphiti | Zep LongMemEval 71.2% vs 全上下文 60.2%，上下文 1.6k vs 115k；mem0 声称 p95 -91%、token -90%；但 DMR 全上下文基线 98%，Letta/Mem0 结果互相质疑。弱-中 | 运维/一致性/评测不可比 | 中等，不建议先做 | P2 |
| Skills 渐进披露 | Anthropic Agent Skills（2025-10，2026-10 捐 AAIF）、Codex、deepagents、ADK | 三级：元数据约 100 token/技能，正文<5k，引用按需；Codex 初始列表默认 2%/8k 字符，可调 10k；Claude Code 压缩后按共享预算重注入。中 | 描述预算有限；选择可能错 | 很适合：go:embed + frontmatter + 版本/来源签名 | P1 |

### 1.3 工具、证据、报告

| 模式 | 代表 | 证据 | 代价 | Go 适配 | 优先级 |
|---|---|---|---|---|---|
| ACI/单一 bash 接口 | SWE-agent、mini-SWE-agent | mini-SWE-agent 仅 bash >74%；ACI 比 shell-only 相对 +64%；但 harness-model 配对可差 44pp。强 | 单一 bash 难结构化证据 | 很适合：exec + 结构化 wrapper 并存 | P0 |
| 工具目录治理：命名空间+合并+可见上限 | Anthropic 工具指南、Manus mask-don't-remove | 5 个 MCP server 58 工具约 55k token，曾见 134k；>30-50 工具选择准确率下降；合并 schedule_event 减工具数与上下文。中-强 | 设计成本；合并降灵活性 | 很适合：`recon.http.probe` 命名空间 + 风险等级/scope | P0 |
| 工具搜索 + 程序化工具调用 | Anthropic Tool Search、PTC | Tool Search 上下文 77k→8.7k（-85%），Opus4 49%→74%；PTC 43,588→27,297 token（-37%），200KB 原始数据只回 1KB。中 | 多一轮检索；沙箱执行 | 很适合：bleve/BM25 + 受限 runner | P1 |
| MCP/A2A 互操作 | MCP 2025-11-25、A2A 1.0 | MCP tasks durable 状态机；elicitation form/url；A2A Agent Card/Task/Artifact。强/弱 | 攻击面扩大；工具注入/越权 | MCP 客户端优先；A2A P2 | P1/P2 |
| 证据账本 + 独立引用 pass | Anthropic CitationAgent、A2A Artifact、渗透 milestone 评分 | 研究系统单独 CitationAgent 做 claim→source；阶段 milestone 比最终 flag 更能诊断。中 | 多一轮调用；存储成本 | 很适合：内容寻址 + findings↔evidence 多对多 | P0 |

### 1.4 运行时、安全、评测

| 模式 | 代表 | 证据 | 代价 | Go 适配 | 优先级 |
|---|---|---|---|---|---|
| 持久化执行/checkpoint/resume | LangGraph、ADK Go 2.0、Codex sessions、Temporal/Restate | 每 super-step checkpoint；pending writes 恢复不重跑；durability 三档；ADK 从 session history 重建。强/中 | 存储/序列化；幂等要求 | 很适合：Temporal Go SDK 或事件日志 + outbox | P0 |
| Idle-stop/wrap-up/目标评估器 | 本仓 idlestop/wrapup；Claude Code /goal + Stop/TeammateIdle；SDK max_turns/max_budget_usd | 本仓生产：done 18 / exhausted 99 / blocked 82，exhausted 是 done 5.5 倍；summary 均 737 字、最长 2267；三代接续链。Claude Code /goal 独立小模型判定，连续无工具调用即停。强 | 评估器成本；误停 | 很适合：已有双钩子，补 USD 预算与评估器 | P0 |
| 预算治理 + 模型路由 | Claude Code max_budget_usd；Anthropic effort 档；Batch API | Opus 5.5 SWE-bench Pro 子集：low 87.4%/$0.11、medium 92.8%/$0.21、high 95.3%/$0.29、xhigh 96.7%/$0.74；研究 high 比 low 高 3.3 分贵 3.2 倍；Batch 五折。中-强 | 路由错误降质；预算滞后 | 很适合：预算结构体随 ctx 传递，每步扣费 | P0 |
| HITL + 沙箱网络作用域 | Claude Code permission modes、Codex approvals、LangGraph interrupt、E2B/Firecracker/Daytona/gVisor | AutoPenBench 21% vs 64%；Claude Code 连续 3 次/累计 20 次拦截转人工；E2B create→first command 中位 264ms，Daytona 819ms，突发下 37% 成功。强/中 | 吞吐下降；沙箱成本 | 很适合：审批 DB 信号；scope 前置 + 沙箱 egress 双层 | P0 |
| OTel + 轨迹评测 | OTel GenAI semconv、Langfuse/Phoenix、pass^k | OTel 定义 invoke_agent/plan/execute_tool span 与 gen_ai.*；Langfuse 每次模型调用单独 generation、工具单独 tool、优先二值评分；Terminal-Bench 固定 wall-clock 会改变 20pp 差距。中-强 | 埋点/存储；评测维护 | 很适合：OTel Go SDK + OTLP，trace_id 写 evidence | P1 |

---

## 2. 十条最值得吸收的做法

1. **稳定前缀当一等公民**：system prompt/工具定义/scope/输出规范放最前，一次 engagement 内不变；时间戳/随机 ID/动态工具清单放末尾或外部；JSON 固定字段序，禁 map 迭代序；记录 prefix hash 与缓存命中率。
2. **上下文缩减两段**：工具结果 full 进 artifact store，compact 只留 path/URL/hash/一行摘要；达阈值先压最老 50%，保留最近 3-5 对完整；收益不足才摘要；摘要基于 full，摘要后重注入 scope/规则/当前计划。
3. **外部状态用 schema**：plan.json（任务/假设/验证步骤/状态/evidence_ids）、progress.md（当前假设/已排除/下一步）、findings.jsonl（只追加）；agent 只能改状态字段，不能改验收标准；新 session 先读状态、跑冒烟。
4. **Planner 独立成 agent，用进度账本重规划**：planner 不调执行工具；输入目标/scope/证据摘要/上轮结果；输出 1-3 个下一步 + 成功判据 + 放弃条件；连续 N 轮无新增证据重规划；planner 与 worker 不同提示/模型。
5. **Worker 交接契约**：只给最小上下文；返回结构化结果 + artifact 引用，摘要 1-2k token；worker 只能“提案” finding，不能直接写全局账本；写入单线程，只读侦察可并行。
6. **工具目录少而深**：命名空间 `recon.http.probe`；把 5-10 个 CLI 合并成任务级工具；默认暴露 20-30 个高频工具，其余延迟 + BM25；结果 25k token 上限，支持 concise/detailed；错误消息可执行。
7. **Skills 渐进披露**：启动只加载 name/description（约 100 token），命中读正文（<5k），脚本只回输出；声明适用阶段/工具/风险/验证清单；压缩后按预算重注入已激活 skill。
8. **证据账本 + 独立报告 pass + 完成闸门**：工具输出内容寻址；finding 只存 evidence_ids，必须含 claim/severity/asset/复现命令/请求响应 hash/时间戳/confidence；报告 agent 只读 evidence DB 逐条引用；无证据自动降级“待验证”；报告前一致性检查。
9. **持久化执行**：每 step 追加事件（step_id/parent/type/input_hash/output_hash/status/cost/idempotency_key）；副作用工具去重表；恢复构造“上次进度+未完成动作+最近证据”resume prompt；终止原因枚举 success/budget/timeout/no_progress/scope_violation/error。
10. **预算 + 无进展检测 + 强制收尾**：turns/USD/wall-clock 三类上限，80% 预警；每轮记录新增证据/成功工具/新资产，连续 N 轮为 0 触发收尾；收尾固定：落盘 findings→标记未验证→报告骨架→handoff→typed reason 退出；高风险 HITL；便宜模型枚举/解析，强模型规划/利用链。

## 3. 五条反模式

1. **planner 一次生成固定长计划，worker 盲目执行**：渗透证据驱动，初始计划必然过时；PentestEval 端到端 31%，失败集中在阶段；应滚动重规划 + 阶段门禁。
2. **多个 agent 并行写共享状态/自由协作**：动作携带隐式决策，并行写者冲突；多 agent 只做只读情报 + 单线程写入。
3. **每个 CLI 1:1 包成工具**：工具 >30-50 选择准确率下降；5 个 MCP 55k token；应任务级合并、命名空间、延迟加载、结果 token 上限。
4. **过早、激进、不可逆摘要**：报告需要原始请求/响应/payload/时间戳；先可逆压缩，证据先落盘再压缩。
5. **没有预算/停止条件的自主循环，把反思当能力**：Terminal-Bench 50%+ 失败是超时；无成本控制的 accuracy 没意义；简单 retry 基线可打平复杂 System 2 agent；正确做法是可验证完成判据 + 三类预算 + 无进展检测 + 强制收尾。

> 谨慎项：不要把专用记忆服务/向量库当第一优先级；DMR 全上下文 98%，Letta 文件系统 LoCoMo 74% 高于 Mem0 报告；先用文件 + SQL + 好的检索工具。

---

## 4. 与本仓库现状对照

**已有**：planner 事件驱动唯一 intent 生成器（agent/planner.go）、worker（agent/worker.go）、idlestop（PreToolUse+Stop 双钩子，生产 telemetry）、compaction（冷节点 digest，6 节点/块、4 路并发、64k 输出预算）、deferred（技能门控 MCP + 恢复重放）、goal_gate（能力型目标不得用否定证据结案）、wrapup（按 agent 配置收尾）、terminalreason、taskclock、evidence/store（内容寻址、崩溃一致性、traffic 快照）、toolcatalog（DB 覆盖描述/schema/绑定）、verification_depth（危害证明硬尾巴）。

**建议补**：
1. **预算维度**：现有 MaxTurns/MaxDuration/task clock，缺 per-task/per-intent USD/token 预算与 80% 预警；cost 作为事件字段，收尾原因加 budget。
2. **工具可见性上限与检索**：deferred 已处理 MCP 延迟，但目录继续增长需“默认 20-30 + BM25 搜索 + 结果 25k 上限”硬约束。
3. **技能元数据预算**：27 个技能，建议初始列表设 token/字符上限（如 2%/8k），超限截描述，压缩后按预算重注入已激活技能。
4. **评测 harness**：用 Vulhub/DVWA/Juice Shop/AD 靶场做 20-50 场景，按 PentestEval 阶段评分 + pass^k + 每解一题成本回归；比再加一个 agent 角色更能提升长期完成率。
5. **OTel 语义对齐**：映射 invoke_agent/plan/execute_tool/chat span，打全 gen_ai.usage.*、模型、工具名、错误类型，便于接 Langfuse/Phoenix。

---

## 5. 参考链接

**Anthropic/Claude Code**：building effective agents、effective context engineering、effective harnesses for long-running agents、multi-agent research system、writing tools for agents、Agent Skills、AAIF、advanced tool use、context management、Claude Code how it works/sub-agents/skills/checkpointing/best practices/agent teams/goal/agent loop/hooks、pricing、context editing、tool search。

**OpenAI/Codex**：run long horizon tasks with Codex、harness engineering、Codex prompting guide、Agents API、sandbox agents、Agents SDK、multi-agent。

**框架/协议**：LangGraph overview/checkpointers/interrupts、LangChain 1.0、Deep Agents、AutoGen v0.4、Magentic-One、ADK Go 2.0、adk-go、MCP 2025-11-25（tasks/elicitation/tools）、A2A 1.0。

**Manus/复盘**：Context Engineering for AI Agents、Cognition Don't Build Multi-Agents / Multi-Agents: What's Actually Working、12-Factor Agents。

**长任务/上下文/记忆证据**：METR long tasks、Chroma context rot、Letta sleep-time compute / memory benchmark、Mem0 论文、Zep 论文、SWE-agent ACI、mini-SWE-agent、harness-model 受控实验、AI Agents That Matter、Agentless、Terminal-Bench 2.0/2.1、SWE-Bench Pro V2、OSWorld 2.0、ComponentBench、Browser Use 工程、OTel GenAI agent spans、Langfuse best practices。

**渗透证据**：PentestEval（346 任务、阶段评分、端到端 31%）、CVE-Bench（最佳 agent 13%）、AutoPenBench（自主 21% vs 辅助 64%）、CAIBench、PACEbench、Red-MIRROR 预印本、LLM 渗透测试综述。

**沙箱**：E2B/Daytona/Modal 独立启动基准、2026 沙箱横评、自托管 Firecracker/gVisor、Temporal Go SDK。

（完整 URL 见调研原始输出；需要时可按条目检索。）
