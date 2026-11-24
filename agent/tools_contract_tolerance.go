package agent

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/chu0119/pojun/db"
)

// normalizeToolInput tolerates the malformed-but-recoverable shapes models
// routinely send to write tools (v0.4.101 P0-4):
//
//  1. a JSON string containing the real object;
//  2. a single wrapper object: {"finding": {...}} / {"fact": {...}} / {"data": {...}};
//  3. aliases: vulnerability/type -> vulnclass, desc -> summary, proof/poc -> evidence;
//  4. scalar-to-list: asset_ids: 12 / "12,13" -> [12,13];
//  5. scalar-to-string: severity 高危 -> high, evidence object -> JSON text.
//
// It never invents content: missing required fields still fail in the handler.
// The goal is to stop discarding a confirmed finding over a stray wrapper key.
func normalizeToolInput(raw json.RawMessage, wrappers ...string) (json.RawMessage, error) {
	v, err := decodeJSONValue(raw)
	if err != nil {
		return nil, fmt.Errorf("入参不是合法 JSON：%v；请传一个 JSON 对象，如 {\"vulnclass\":\"...\",\"severity\":\"high\",\"summary\":\"...\"}", err)
	}
	if s, ok := v.(string); ok {
		// raw was a quoted JSON string; parse its contents.
		v, err = decodeJSONValue(json.RawMessage(s))
		if err != nil {
			return nil, fmt.Errorf("入参是字符串但内容不是 JSON 对象：%v", err)
		}
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("入参必须是 JSON 对象，实际是 %T", v)
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("入参是空对象")
	}
	normalizeMapFields(m, wrappers...)
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func decodeJSONValue(raw json.RawMessage) (any, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}

var toolFieldAliases = map[string][]string{
	"vulnclass":             {"vuln_class", "vulnerability", "vuln_type", "vulntype", "class", "category", "type"},
	"name":                  {"title", "vuln_name", "finding_name"},
	"summary":               {"desc", "description", "finding_summary"},
	"detail":                {"details", "detail_text"},
	"evidence":              {"proof", "poc", "payload", "evidence_text", "request_response", "http_request", "request", "response"},
	"severity":              {"risk", "level", "severity_level"},
	"asset_ids":             {"assets", "asset_id", "assetIds", "assetid", "target_ids", "targets"},
	"intent_id":             {"intentId", "intent", "node_id"},
	"root_cause_key":        {"rootCauseKey", "root_cause", "rootcause"},
	"verification_strategy": {"strategy", "verify_strategy", "verification", "verify"},
}

func normalizeMapFields(m map[string]any, wrappers ...string) {
	// 1. unwrap a single nested object ({"finding": {...}})
	for _, w := range wrappers {
		sub, ok := m[w]
		if !ok {
			continue
		}
		var sm map[string]any
		switch x := sub.(type) {
		case map[string]any:
			sm = x
		case string:
			_ = json.Unmarshal([]byte(x), &sm)
		}
		if sm != nil {
			delete(m, w)
			for k, v := range sm {
				if _, exists := m[k]; !exists {
					m[k] = v
				}
			}
		}
	}
	// 2. aliases (canonical wins)
	for canonical, aliases := range toolFieldAliases {
		if _, ok := m[canonical]; ok {
			continue
		}
		for _, a := range aliases {
			if v, ok := m[a]; ok {
				m[canonical] = v
				delete(m, a)
				break
			}
		}
	}
	// 3. scalar coercions
	if v, ok := m["severity"]; ok {
		m["severity"] = normalizeSeverityText(coerceText(v))
	}
	if v, ok := m["vulnclass"]; ok {
		s := coerceText(v)
		if s != "" {
			m["vulnclass"] = db.NormalizeVulnClass(s)
		}
	}
	for _, key := range []string{"summary", "name", "detail", "evidence", "root_cause_key", "hypothesis", "success_criteria", "verification_strategy"} {
		if v, ok := m[key]; ok {
			m[key] = coerceText(v)
		}
	}
	if v, ok := m["intent_id"]; ok {
		m["intent_id"] = coerceIDValue(v)
	}
	if v, ok := m["asset_ids"]; ok {
		m["asset_ids"] = coerceIDList(v)
	}
	// 4. facts batch: normalize each element and tolerate a JSON-string array
	if v, ok := m["facts"]; ok {
		if s, isStr := v.(string); isStr {
			var arr []any
			if json.Unmarshal([]byte(s), &arr) == nil {
				v = arr
				m["facts"] = arr
			}
		}
		if arr, isArr := v.([]any); isArr {
			for _, item := range arr {
				if im, isMap := item.(map[string]any); isMap {
					normalizeMapFields(im)
				}
			}
		}
	}
}

// coerceText renders any value as text; objects/arrays become JSON.
func coerceText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case json.Number:
		return x.String()
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Sprint(x)
		}
		return string(b)
	}
}

func normalizeSeverityText(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "严重", "危急", "p0":
		return "critical"
	case "high", "高", "高危", "p1":
		return "high"
	case "medium", "中", "中危", "moderate", "p2":
		return "medium"
	case "low", "低", "低危", "info", "informational", "p3":
		return "low"
	}
	return s
}

// coerceIDValue turns "12"/12/12.0 into a JSON number for intent_id.
func coerceIDValue(v any) any {
	switch x := v.(type) {
	case float64:
		return json.Number(strconv.FormatInt(int64(x), 10))
	case json.Number:
		return x
	case string:
		s := strings.TrimSpace(x)
		if _, err := strconv.ParseInt(s, 10, 64); err == nil {
			return json.Number(s)
		}
	}
	return v
}

// coerceIDList accepts [1,2], 1, "1,2", ["1","2"], and filters junk.
func coerceIDList(v any) []any {
	var out []any
	var add func(any)
	add = func(x any) {
		switch n := x.(type) {
		case float64:
			if n > 0 {
				out = append(out, json.Number(strconv.FormatInt(int64(n), 10)))
			}
		case json.Number:
			if i, err := n.Int64(); err == nil && i > 0 {
				out = append(out, n)
			}
		case string:
			s := strings.TrimSpace(n)
			if s == "" {
				return
			}
			if strings.ContainsAny(s, ",， ") {
				for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '，' || r == ' ' }) {
					add(part)
				}
				return
			}
			if i, err := strconv.ParseInt(s, 10, 64); err == nil && i > 0 {
				out = append(out, json.Number(s))
			}
		}
	}
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			add(item)
		}
	case []int64:
		for _, item := range x {
			add(float64(item))
		}
	default:
		add(v)
	}
	return out
}

// deriveVulnClass is a last-resort classifier when the model omitted
// vulnclass but the summary/evidence clearly names a class. Returns "" when
// nothing matches (caller decides whether to reject or use 其他).
func deriveVulnClass(text string) string {
	low := strings.ToLower(text)
	switch {
	case strings.Contains(low, "sql") && (strings.Contains(low, "注入") || strings.Contains(low, "inject")):
		return "注入"
	case strings.Contains(low, "xss") || strings.Contains(low, "跨站脚本"):
		return "XSS"
	case strings.Contains(low, "ssrf") || strings.Contains(low, "服务端请求伪造"):
		return "SSRF"
	case strings.Contains(low, "idor") || strings.Contains(low, "越权") || strings.Contains(low, "未授权"):
		return "未授权访问"
	case strings.Contains(low, "rce") || strings.Contains(low, "命令执行") || strings.Contains(low, "代码执行"):
		return "RCE"
	case strings.Contains(low, "上传") || strings.Contains(low, "upload"):
		return "任意文件上传"
	case strings.Contains(low, "文件读取") || strings.Contains(low, "路径穿越") || strings.Contains(low, "lfi"):
		return "任意文件读取"
	case strings.Contains(low, "信息泄露") || strings.Contains(low, "info leak"):
		return "信息泄露"
	case strings.Contains(low, "弱口令") || strings.Contains(low, "weak password"):
		return "弱口令"
	case strings.Contains(low, "认证绕过") || strings.Contains(low, "auth bypass"):
		return "认证绕过"
	case strings.Contains(low, "反序列化"):
		return "反序列化"
	case strings.Contains(low, "csrf"):
		return "其他"
	}
	return ""
}
