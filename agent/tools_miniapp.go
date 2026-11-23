package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// miniapp_audit（v0.4.99）：微信小程序解包产物静态审计。
//
// 与 js_audit 共用同一份内嵌 Python 脚本（js_audit.py 的 --dir 分支），
// 不复制扫描规则；工具本身只做路径校验与命令组装，实际扫描交给 Bash。
// 这样既不改 js_audit 的 DB schema（老库 required 不会自动放开），
// 又能让 worker/pentest 直接看到“小程序目录审计”这个入口。
func (t *ToolSet) miniappAudit() actool.CoreTool {
	return readTool(
		"miniapp_audit",
		"微信小程序解包产物静态审计（纯本地，不发请求；OSV 依赖查询除外）："+
			"扫描接口/域名、硬编码密钥（AppSecret/AK/SK/JWT/AES/地图 key）、云开发 env/云函数/集合、"+
			"签名候选、页面路由、sourceMap 与依赖漏洞。输入解包目录（通常 <taskRoot>/miniapp/<appid>/source）。"+
			"返回一条命令交给 Bash 执行；输出 report.json / endpoints.txt / secrets.txt（密钥脱敏）。",
		obj(map[string]any{
			"dir":   str("解包产物目录：相对本次 run 目录，或任务根内的绝对路径（通常 <taskRoot>/miniapp/<appid>/source）"),
			"appid": str("小程序 AppID（可选，仅用于报告标注；不要传微信账号 wxid）"),
			"osv":   map[string]any{"type": "boolean", "description": "是否查询 OSV 依赖漏洞（默认 true）"},
		}, "dir"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Dir   string `json:"dir"`
				AppID string `json:"appid"`
				OSV   *bool  `json:"osv"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			dir := strings.TrimSpace(a.Dir)
			if dir == "" {
				return actool.Errorf("dir 不能为空"), nil
			}
			if strings.TrimSpace(t.runDir) == "" {
				return actool.Errorf("miniapp_audit 未启用: 本次 run 没有可用的工作目录"), nil
			}
			runDir := t.runDir
			taskRoot := runDir
			// worker 的 runDir 形如 tasks/<id>/i<N>；任务根是它的父目录。
			if ok, _ := regexp.MatchString(`^i[0-9]+$`, filepath.Base(runDir)); ok {
				taskRoot = filepath.Dir(runDir)
			}
			abs := dir
			if !filepath.IsAbs(abs) {
				abs = filepath.Join(runDir, abs)
			}
			abs = filepath.Clean(abs)
			if resolved, err := filepath.EvalSymlinks(abs); err == nil {
				abs = resolved
			}
			if resolved, err := filepath.EvalSymlinks(taskRoot); err == nil {
				taskRoot = resolved
			}
			rel, err := filepath.Rel(taskRoot, abs)
			if err != nil || strings.HasPrefix(rel, "..") {
				return actool.Errorf(fmt.Sprintf("dir 超出任务目录范围: %s", a.Dir)), nil
			}
			info, err := os.Stat(abs)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("目录不存在或不可读: %v", err)), nil
			}
			if !info.IsDir() {
				return actool.Errorf(fmt.Sprintf("dir 不是目录: %s", a.Dir)), nil
			}
			script := t.ensureJsAuditScript()
			if script == "" {
				return actool.Errorf("miniapp_audit 未启用: 脚本落盘失败"), nil
			}
			out := filepath.Join(runDir, "miniapp-audit")
			cmd := fmt.Sprintf("python3 %s --dir %s --out %s", script, quoteShell(abs), quoteShell(out))
			if appid := strings.TrimSpace(a.AppID); appid != "" {
				cmd += " --appid " + quoteShell(appid)
			}
			if a.OSV != nil && !*a.OSV {
				cmd += " --no-osv"
			}
			return jsonResult(map[string]any{
				"run_with_bash": cmd,
				"dir":           abs,
				"out":           out,
				"note": "纯本地扫描；report.json 含 routes/endpoints/secrets/cloud/sign_candidates/summary。" +
					"密钥先 record_fact 验证有效性，接口批量 insert_assets(type=endpoint)，" +
					"云环境/函数按 mini-program skill 的 references/04 继续。",
			})
		})
}
