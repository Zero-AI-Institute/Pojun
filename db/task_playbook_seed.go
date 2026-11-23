package db

import (
	"errors"
	"fmt"
)

// 内置任务模板（v0.4.60，PentestAgent Playbook 思路）：把验证过的任务目标结构
// （内部工作流拆解 + 边界纪律——政企/事业单位 Web 站点实测调优过的 goal 格式）
// 做成预置 Playbook，建任务时一键套用，替代空白目标。
//
// 种子策略与拦截规则同款：settings flag 记批次，插过即跳过；用户后续的删除/修改
// 不被复活。intercept_rules 留空——Playbook 只管目标结构，操作约束由 scope 决定。

type builtinTaskPlaybook struct {
	name        string
	description string
	goal        string
}

var builtinTaskPlaybooks = []builtinTaskPlaybook{
	{
		name:        "Playbook：Web 全流程渗透（医院/政企站点）",
		description: "适用：单域名或少量域名的 Web 系统（授权站点+点名入口）。串行五段：资产发现→未授权面探测→业务链路测试→验证留证→出报告。政企/事业单位 Web 站点实测调优的目标结构。",
		goal: `对「{{目标名称}}」授权目标进行完整渗透测试，产出可复现的漏洞报告。**一个目标集合，内部严格按依赖串行推进：资产发现→服务识别→漏洞探测→验证→出报告，不跳步、不重复扫描。**

【授权范围】
- 授权类型：用户授权的渗透测试（按任务描述里的范围说明执行；范围外资产只做归属核实记录，不测试）。
- 点名入口：以任务描述中给出的 URL/主机为准，全部必测。
- IP 资产：仅纳入可由证书/备案/ASN 证明归属目标主体的服务；同 IP/同网段明确属于第三方的业务不得扩展测试。

【内部工作流（串行，自行拆解规划）】
1. 资产发现与识别：DNS/子域/证书透明度/端口与服务识别/HTTP 指纹/目录与接口发现/前端 JS 硬编码接口与密钥（SPA 站点必跑 js_audit 查 sourcemap 泄露）；
2. 未授权面漏洞探测：信息泄露（.git/.env/备份/Swagger/Actuator/phpinfo/目录遍历/源码泄露）、未授权访问、鉴权缺失、CORS 配置、错误信息泄露、已知组件 CVE（先指纹确认再验证）；
3. 业务链路测试：登录/重置/改绑链路、支付/优惠券/积分逻辑、IDOR 与批量赋值——只验证到"能读到非本人数据"即止，禁止批量拉取业务数据；
4. 验证与留证：每个漏洞给出最小可复现请求与响应（curl 命令+关键输出），HTTP 漏洞保留真实流量 ID 并绑定；严重性严格按证据分级（L3 才报 high/critical，L2 最多 medium）；
5. 出报告：逐条登记并撰写详细报告（概述/影响/复现步骤/证据/修复建议），最后输出资产清单、漏洞清单（按风险排序）、修复优先级。

【边界】
- 生产环境只读/最小验证；不破坏可用性、不删改业务数据、不批量注册；
- 敏感数据点到为止；无响应或强 WAF 拦截记录后转下一目标，不反复硬打。`,
	},
	{
		name:        "Playbook：内网域渗透（拿立足点后向域推进）",
		description: "适用：已有外网立足点或域内可达性（VPN/办公网）。流程：立足点稳定化→本机提权→凭据收集→横向移动→域内专项（Kerberoast/DCSync/ADCS）→数据获取证明。每步留证，横向只打已证明归属的网段。",
		goal: `以内网可达性为起点完成域渗透测试，产出攻击路径报告。**串行推进：立足点→提权→凭据→横向→域专项→数据证明，每步先落事实再进下一步。**

【授权范围】
- 以任务描述给出的内网网段/跳板为边界；未证明归属的主机不横向。

【内部工作流】
1. 立足点稳定化与信息收集：身份/权限/网络位置/防御面（EDR/杀软/出网限制），落初始访问 fact；
2. 本机提权：sudo -l/SUID/定时任务/服务配置（Linux）、whoami /priv/未引号路径/存储凭据（Windows）→ search_vulns 查内核/组件提权 CVE；
3. 凭据收集：配置文件/SSH 私钥/历史命令/LSASS/SAM/DPAPI/GPP——凭据全文写 fact（不缩写不掩码），并逐组验证可用性；
4. 横向移动：凭据直连 SSH/RDP/SMB/WinRM → impacket 族（psexec/wmiexec/secretsdump）→ 隧道（chisel/ligolo）→ 收敛扫描已证明网段；
5. 域内专项：域枚举 → Kerberoast/AS-REP → 委派 → ADCS（certipy find -vulnerable）→ DCSync（需权限，只导最小集）；
6. 数据获取证明：目标数据只读最小样本，save_evidence 留证，绑定流量。

【边界】
- 域控与生产主机不做写操作；凭据喷洒先查锁定策略、最多 2-3 次；
- 权限维持只做可行性演示（落 fact），不实际部署；
- 被 EDR/策略拦截 → 记录拦截形态与前置条件，不反复硬打。`,
	},
	{
		name:        "Playbook：APP 逆向 + API 渗透",
		description: "适用：目标是移动 APP（APK/IPA）及其后端 API。流程：静态分析提取接口与密钥→动态抓包补全→API 越权/注入测试→客户端漏洞验证（导出组件/WebView/证书校验）→报告。",
		goal: `对「{{APP 名称与后端 API}}」完成移动端渗透测试，产出漏洞报告。**核心思路：逆向拿钥匙，服务端才是主战场。**

【授权范围】
- APP 本体与描述中列出的后端域名；逆向只用于发现接口与凭据，服务端测试只打授权域名。

【内部工作流】
1. 静态分析：apktool/jadx 反编译 → 提取全部接口、baseURL、签名算法、硬编码 AK/SK/token（全文落 fact）→ 导出组件/deep-link 清单；
2. 动态补全：挂代理抓包（SSL 校验仅对自有测试包做绕过）→ 核对静态接口与真实流量差异；
3. API 渗透：用还原的签名算法直接调后端接口 → 越权（换 id/换 token）/未授权/注入/逻辑（对照 api-security-testing 流程）→ 每条最小样本留证；
4. 客户端验证：导出组件启动参数注入、WebView 注入、allowBackup 导出、证书校验缺失（自有包演示）；
5. 报告：接口泄露/硬编码凭据/越权读数据/组件暴露逐条登记，附逆向证据与接口复现。

【边界】
- 不逆向/测试授权外的 APP；不绕过付费与版权保护做非测试用途；
- 涉及用户隐私的接口只证明可读一条，不批量拉取。`,
	},
	{
		name:        "Playbook：纯侦察·资产盘点（不下钻利用）",
		description: "适用：只做资产清点与暴露面盘点（如客户只要资产清单），或大范围授权的第一阶段。产出：资产清单+指纹+暴露面风险列表，不做利用验证。",
		goal: `对「{{目标域名/IP 范围}}」完成资产盘点，产出资产清单与暴露面风险列表。**本任务只侦察不利用**：不做漏洞利用、不做爆破、不做目录暴破，只做存在性与指纹确认。

【内部工作流】
1. 归属核实：备案/证书/whois/ASN，逐条记录归属证据；
2. 资产发现：子域枚举（被动优先）/端口服务识别/HTTP 指纹——http_probe 批量探活；
3. 暴露面标注：管理后台暴露、调试端点（Swagger/Actuator/Druid）、过期组件版本、默认页、可匿名访问的服务——只记录「存在+指纹」，不深入；
4. 入库：全部资产 insert_assets 并归属企业；每类给出暴露面风险摘要。

【产出】
- 资产清单（域名/IP/端口/服务/指纹）；暴露面风险列表（按风险排序，附证据截图）；归属存疑项列表（记录不测试）。`,
	},
}

// v0.4.99：第二批内置 Playbook。独立 flag，老库 task_playbooks_v1=done 不会
// 让本批永久不可见（这是第一批 seed 设计的已知迁移坑）。
var builtinTaskPlaybooksV2 = []builtinTaskPlaybook{
	{
		name:        "Playbook：微信小程序渗透（包→接口→越权→云开发）",
		description: "适用：用户上传 wxapkg/zip 或给出小程序 AppID，要对其做安全测试。流程：安全解包→静态提取接口/密钥/云环境→登录态与越权→云开发/支付/开放能力→证据与报告。",
		goal: `对「{{小程序名称/AppID}}」完成微信小程序渗透测试，产出可复现的漏洞报告。**核心思路：包是入口，后端才是主战场。**

【内部工作流】
1. 输入与资产：定位 uploads 下的 .wxapkg/.zip/目录，提取 AppID（wx+16 hex；不要用 wxid）；insert_assets(type=app, bundle_id=<AppID>, app_name=<名称>)。
2. 解包：加载 Skill("mini-program")，执行 ${SKILL_DIR}/scripts/miniapp_unpack.sh --in <包> --out <taskRoot>/miniapp --appid <AppID>；产物 source/ 为质量分最高者，manifest.json 记录包哈希/工具/质量分。质量 partial 时标注并以动态验证补齐。
3. 静态审计：调用 miniapp_audit(dir=<taskRoot>/miniapp/<AppID>/source, appid=<AppID>)；把 endpoints 批量 insert_assets(type=endpoint)，secrets 全文 record_fact（报告脱敏），云 env/函数/集合单独记录。
4. 路由与高价值页面：读 app.json/app-config.json，列出主包/分包/插件页面；标记登录/支付/订单/地址/会员/上传页面。
5. 动态验证（目标可达时）：
   - 抓包：按 skill references/02 配 PC 微信 Proxifier/模拟器代理；或导入用户提供的请求样本。
   - 登录态：session_login 建 A/B 双身份；对每个敏感接口跑未授权/水平/垂直越权矩阵（无 token、空 token、A→B、普通→管理、过期/伪造 token）。
   - 云开发：按 references/04 测云函数鉴权、DB/存储规则、环境共享、未登录模式。
   - 支付/开放能力：按 references/05 逐项；只做测试商户/沙箱/最小金额。
6. 证据：每条候选漏洞 save_evidence（源码 file:line、请求响应、复现命令）；high/critical 过 evidence_check。
7. 报告：report_finding（AppID + 页面路径 + 接口 + 请求响应 + 影响 + 修复）；输出资产清单、接口清单、漏洞清单（按风险排序）、修复优先级。
8. 复测：修复后按 finding retest 流程复测。`,
	},
}

// seedBuiltinTaskPlaybooksV2 插入第二批内置模板（独立批次 flag）。
func (d *DB) seedBuiltinTaskPlaybooksV2() error {
	const flag = "task_playbooks_v2"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	for _, pb := range builtinTaskPlaybooksV2 {
		in := TaskTemplateInput{
			Name:        pb.name,
			Description: pb.description,
			Goal:        pb.goal,
		}
		if _, err := d.CreateTaskTemplate(in); err != nil {
			if errors.Is(err, ErrTaskTemplateNameConflict) {
				continue
			}
			return fmt.Errorf("playbook v2 %q: %w", pb.name, err)
		}
	}
	return d.SetSetting(flag, "done")
}

// seedBuiltinTaskPlaybooks 种子内置任务模板（PentestAgent Playbook 思路落地）。
// settings flag 记批次；插过即跳过——用户后续删除/修改不复活。
func (d *DB) seedBuiltinTaskPlaybooks() error {
	const flag = "task_playbooks_v1"
	if v, _, _ := d.GetSetting(flag); v == "done" {
		return nil
	}
	for _, pb := range builtinTaskPlaybooks {
		in := TaskTemplateInput{
			Name:        pb.name,
			Description: pb.description,
			Goal:        pb.goal,
		}
		if _, err := d.CreateTaskTemplate(in); err != nil {
			// 已存在同名模板 = 跳过（用户可能改过内容，种子不覆盖）；其余如实返回。
			if errors.Is(err, ErrTaskTemplateNameConflict) {
				continue
			}
			return fmt.Errorf("playbook %q: %w", pb.name, err)
		}
	}
	return d.SetSetting(flag, "done")
}
