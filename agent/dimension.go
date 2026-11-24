package agent

import (
	"encoding/json"
	"strings"
)

// 意图维度（v0.7.0）：用于「同资产×同手法零产出」的确定性去重。
// planner 可以显式给 dimension，也可以由 summary 推断；两者都归一到这里。
const (
	dimRecon      = "recon"
	dimAuthz      = "authz"
	dimInjection  = "injection"
	dimUpload     = "upload"
	dimSSRF       = "ssrf"
	dimRCE        = "rce"
	dimCredReuse  = "cred-reuse"
	dimDataExport = "data-export"
	dimPayment    = "payment"
	dimPrivesc    = "privesc"
	dimLateral    = "lateral"
)

var dimensionAliases = map[string]string{
	"recon": "recon", "reconnaissance": "recon", "侦察": "recon", "信息收集": "recon",
	"authz": "authz", "authorization": "authz", "idor": "authz", "越权": "authz", "权限": "authz",
	"injection": "injection", "sqli": "injection", "xss": "injection", "ssti": "injection", "注入": "injection",
	"upload": "upload", "上传": "upload", "文件上传": "upload",
	"ssrf": "ssrf", "ssrf-probe": "ssrf",
	"rce": "rce", "command": "rce", "exec": "rce", "命令执行": "rce", "代码执行": "rce",
	"cred-reuse": "cred-reuse", "cred": "cred-reuse", "credential": "cred-reuse", "凭据": "cred-reuse", "密码复用": "cred-reuse",
	"data-export": "data-export", "data": "data-export", "export": "data-export", "取数": "data-export", "数据导出": "data-export",
	"payment": "payment", "pay": "payment", "支付": "payment", "资金": "payment", "订单": "payment",
	"privesc": "privesc", "privilege": "privesc", "提权": "privesc",
	"lateral": "lateral", "横向": "lateral",
}

// dimensionInferRules 按优先级从高到低匹配 summary。
var dimensionInferRules = []struct {
	dim string
	kws []string
}{
	{dimPayment, []string{"支付", "改价", "回调", "结算", "资金", "退款", "payment", "checkout", "订单状态"}},
	{dimCredReuse, []string{"凭据", "口令", "密码", "复用", "ak/sk", "accesskey", "token", "credential", "login as"}},
	{dimPrivesc, []string{"提权", "root", "sudo", "suid", "系统权限", "privesc"}},
	{dimLateral, []string{"横向", "内网", "跳板", "lateral", "pivot"}},
	{dimUpload, []string{"上传", "upload", "文件包含", "解析"}},
	{dimRCE, []string{"命令执行", "代码执行", "rce", "getshell", "webshell", "反序列化", "模板注入", "ssti"}},
	{dimSSRF, []string{"ssrf", "元数据", "metadata", "内网探测", "回连"}},
	{dimInjection, []string{"注入", "sqli", "sql", "xss", "越权参数", "injection"}},
	{dimDataExport, []string{"取数", "导出", "批量数据", "未授权读", "数据面", "export", "dump"}},
	{dimAuthz, []string{"越权", "idor", "权限绕过", "未授权访问", "authz"}},
	{dimRecon, []string{"侦察", "枚举", "扫描", "指纹", "目录", "子域", "端口", "recon"}},
}

func normalizeDimension(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if d, ok := dimensionAliases[s]; ok {
		return d
	}
	// 允许 "authz/登录后越权" 这类复合值：取第一个能识别的 token。
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == ',' || r == '|' || r == ' ' }) {
		if d, ok := dimensionAliases[strings.TrimSpace(part)]; ok {
			return d
		}
	}
	return ""
}

func inferDimension(text string) string {
	low := strings.ToLower(text)
	for _, rule := range dimensionInferRules {
		for _, kw := range rule.kws {
			if strings.Contains(low, kw) {
				return rule.dim
			}
		}
	}
	return ""
}

// intentDimension 返回意图最终维度：显式值优先，否则从 summary 推断。
func intentDimension(explicit, summary string) string {
	if d := normalizeDimension(explicit); d != "" {
		return d
	}
	return inferDimension(summary)
}

// IntentDimension is the exported form used by server-side reflection/coverage
// code that already imports agent.
func IntentDimension(explicit, summary string) string { return intentDimension(explicit, summary) }

// dimOther is for findings/facts that can't be attributed to a known dimension.
const dimOther = "other"

var dimensionOrder = []string{
	dimRecon, dimAuthz, dimInjection, dimUpload, dimSSRF, dimRCE,
	dimCredReuse, dimDataExport, dimPayment, dimPrivesc, dimLateral,
}

var dimensionLabels = map[string]string{
	dimRecon:      "侦察/枚举",
	dimAuthz:      "越权/未授权",
	dimInjection:  "注入",
	dimUpload:     "上传/解析",
	dimSSRF:       "SSRF/回连",
	dimRCE:        "命令执行/反序列化",
	dimCredReuse:  "凭据复用",
	dimDataExport: "数据导出",
	dimPayment:    "支付/订单",
	dimPrivesc:    "提权",
	dimLateral:    "横向",
	dimOther:      "未归类",
}

var dimensionTips = map[string]string{
	dimRecon:      "对资产做 DNS/端口/指纹/目录与接口发现，结果写回资产。",
	dimAuthz:      "用 A/B 双身份对照：无 token、空 token、换对象 id、普通用户访问管理接口。",
	dimInjection:  "对参数位/JSON 字段/cookie 做只读注入探测（sqlmap level2 risk1 或等价手工 payload）。",
	dimUpload:     "找上传入口，测类型/后缀/内容/路径绕过（只验证能力，不落地后门）。",
	dimSSRF:       "检查 URL 参数、图片代理、webhook、导出回调；用回连验证。",
	dimRCE:        "按组件指纹查 CVE 后实际触发；无组件线索就记录不适用。",
	dimCredReuse:  "用已获凭据尝试同集群/同模板的登录与接口，先查锁定策略。",
	dimDataExport: "对已证明可达的接口做最小只读取数证明，记录字段与条数。",
	dimPayment:    "测金额/数量/优惠券/订单归属/回调验签/退款幂等，用沙箱或测试商户。",
	dimPrivesc:    "从当前权限尝试提权路径，记录前置条件与验证结果。",
	dimLateral:    "从当前立足点尝试横向可达性，只打已证明归属的网段。",
	dimOther:      "无法归类的发现，人工复核。",
}

// DimensionOrder returns the canonical display/aggregation order.
func DimensionOrder() []string {
	out := make([]string, len(dimensionOrder))
	copy(out, dimensionOrder)
	return out
}

func DimensionLabel(d string) string {
	if s, ok := dimensionLabels[d]; ok {
		return s
	}
	if d == "" {
		return dimensionLabels[dimOther]
	}
	return d
}

func DimensionTip(d string) string { return dimensionTips[d] }

func DimensionKnown(d string) bool {
	_, ok := dimensionLabels[d]
	return ok
}

// IsExploitDimension 判断该维度是否属于「利用/深挖」类：这类意图经常需要
// 连续几十次请求、多步链（拿凭据→登录→提权→取数），租约墙钟要放宽。
func IsExploitDimension(dim string) bool {
	switch dim {
	case dimInjection, dimUpload, dimSSRF, dimRCE, dimCredReuse, dimDataExport, dimPayment, dimPrivesc, dimLateral:
		return true
	}
	return false
}

// ExploitDimensionFromPayload 从意图节点 payload（JSON）取 dimension/summary 并判定。
// payload 解析失败时返回 false（保守：不放宽）。
func ExploitDimensionFromPayload(payload json.RawMessage) bool {
	if len(payload) == 0 {
		return false
	}
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil {
		return false
	}
	explicit, _ := m["dimension"].(string)
	summary, _ := m["summary"].(string)
	if summary == "" {
		summary, _ = m["title"].(string)
	}
	return IsExploitDimension(intentDimension(explicit, summary))
}
