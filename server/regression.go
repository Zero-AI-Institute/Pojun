package server

// 确定性回归检查（v0.4.119 / P2-7）。
//
// 只回放 finding 已绑定的 proof 流量：请求头/正文从 traffic store 现取，不在
// regression 表里保存（避免 Cookie/凭据二次落库）。断言优先用 validator token，
// 其次对照 diff，最后才是弱状态码。POST/PUT/PATCH/DELETE 默认拒绝回放，必须
// 显式 allow_write=true；不自动调度、不自动重试。

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chu0119/pojun/agent"
	"github.com/chu0119/pojun/db"
)

const regressionMaxBody = 2 << 20

func (s *Server) findingRegression(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, http.StatusBadRequest, "finding id 无效")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	finding, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if finding == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	reg, err := pg.GetFindingRegression(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"finding_id": finding.ID, "regression": reg})
}

func (s *Server) checkFindingRegression(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "finding id 无效")
		return
	}
	var body struct {
		AllowWrite bool `json:"allow_write"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)
	pg := s.pg(w)
	if pg == nil {
		return
	}
	finding, err := pg.GetFinding(id)
	if err != nil || finding == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	reg, err := pg.GetFindingRegression(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if reg == nil {
		writeErr(w, 404, "该 finding 没有可重放的回归 spec")
		return
	}
	if !safeReplayMethod(reg.Method) && !body.AllowWrite {
		writeErr(w, 400, "该 spec 是状态变更请求（"+reg.Method+"）；确认目标可重放后传 allow_write=true")
		return
	}
	if s.m.traffic == nil {
		writeErr(w, 503, "流量库未启用，无法回放")
		return
	}
	// 任务级 Program Profile 的 allow/deny/时间窗同样约束人工回放。
	if finding.TaskID != nil && *finding.TaskID > 0 {
		if profile, found, _ := pg.GetTaskProgramProfile(strconv.FormatInt(*finding.TaskID, 10)); found && profile != nil {
			if u, err := url.Parse(reg.URL); err == nil {
				if err := agent.CheckProgramEgressProfile(u.Hostname(), profile, time.Now()); err != nil {
					writeErr(w, 403, err.Error())
					return
				}
			}
		}
	}
	res := s.replayRegression(r.Context(), reg)
	if err := pg.RecordFindingRegressionResult(id, res.Verdict, res.Note); err != nil {
		// 结果写回失败不影响本次判定；日志即可。
	}
	writeJSON(w, 200, map[string]any{
		"finding_id": id, "verdict": res.Verdict, "note": res.Note,
		"status": res.Status, "matched": res.Matched, "assertion": reg.Assertion,
		"regression": reg,
	})
}

type regressionResult struct {
	Verdict string
	Note    string
	Status  int
	Matched bool
}

func safeReplayMethod(m string) bool {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "", "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}

func (s *Server) replayRegression(ctx context.Context, reg *db.FindingRegression) regressionResult {
	reqText, _, err := s.m.traffic.Get(reg.ProofTrafficID)
	if err != nil || strings.TrimSpace(reqText) == "" {
		return regressionResult{Verdict: "not_replayable", Note: "proof 流量已被清理或不可读；不臆造结论"}
	}
	status, body, err := s.replayRawRequest(ctx, reg.URL, reqText)
	if err != nil {
		return regressionResult{Verdict: "inconclusive", Note: "回放失败: " + err.Error()}
	}
	switch reg.Assertion {
	case "token":
		if reg.Token == "" {
			return regressionResult{Verdict: "inconclusive", Status: status, Note: "spec 缺 token"}
		}
		if strings.Contains(body, reg.Token) {
			return regressionResult{Verdict: "pass", Status: status, Matched: true, Note: "响应仍包含 validator token"}
		}
		return regressionResult{Verdict: "fail", Status: status, Note: "响应不再包含 validator token"}
	case "diff":
		if strings.TrimSpace(reg.BaselineTrafficID) == "" {
			return regressionResult{Verdict: "inconclusive", Status: status, Note: "diff spec 缺 baseline 流量"}
		}
		baseReq, _, err := s.m.traffic.Get(reg.BaselineTrafficID)
		if err != nil || strings.TrimSpace(baseReq) == "" {
			return regressionResult{Verdict: "not_replayable", Status: status, Note: "baseline 流量已被清理"}
		}
		baseStatus, baseBody, err := s.replayRawRequest(ctx, reg.URL, baseReq)
		if err != nil {
			return regressionResult{Verdict: "inconclusive", Status: status, Note: "baseline 回放失败: " + err.Error()}
		}
		if status != baseStatus || body != baseBody {
			return regressionResult{Verdict: "pass", Status: status, Matched: true, Note: "proof 与 baseline 仍存在差异"}
		}
		return regressionResult{Verdict: "fail", Status: status, Note: "proof 与 baseline 响应一致，差异未复现"}
	default: // status
		if status == reg.ExpectedStatus {
			return regressionResult{Verdict: "pass", Status: status, Matched: true, Note: "状态码与记录一致（弱断言；建议补 validator/token）"}
		}
		return regressionResult{Verdict: "fail", Status: status, Note: fmt.Sprintf("状态码 %d != 记录 %d", status, reg.ExpectedStatus)}
	}
}

// replayRawRequest parses the raw captured request (request line + headers +
// body) and replays it through the same egress as native HTTP tools.
func (s *Server) replayRawRequest(ctx context.Context, fallbackURL, raw string) (int, string, error) {
	method, target, headers, body := parseRawHTTPRequest(raw)
	if method == "" {
		return 0, "", fmt.Errorf("无法解析请求行")
	}
	targetURL := strings.TrimSpace(target)
	if strings.HasPrefix(targetURL, "/") {
		// baseline/proof 的 path 可能不同：用各自请求行 path + Host 重建，
		// 不能一律回落到 proof 的 fallback URL。
		if base, err := url.Parse(fallbackURL); err == nil && base.Host != "" {
			host := headers.Get("Host")
			if host == "" {
				host = base.Host
			}
			targetURL = base.Scheme + "://" + host + targetURL
		}
	}
	if !strings.HasPrefix(strings.ToLower(targetURL), "http://") && !strings.HasPrefix(strings.ToLower(targetURL), "https://") {
		targetURL = fallbackURL
	}
	u, err := url.Parse(targetURL)
	if err != nil || u.Host == "" {
		return 0, "", fmt.Errorf("URL 无效")
	}
	client, err := s.regressionHTTPClient()
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	for k, vs := range headers {
		ck := strings.ToLower(k)
		switch ck {
		case "host", "content-length", "connection", "proxy-connection", "transfer-encoding":
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if host := headers.Get("Host"); host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, regressionMaxBody))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(b), nil
}

func parseRawHTTPRequest(raw string) (string, string, http.Header, string) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head, body, _ := strings.Cut(raw, "\n\n")
	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return "", "", nil, ""
	}
	parts := strings.Fields(strings.TrimSpace(lines[0]))
	if len(parts) < 2 {
		return "", "", nil, ""
	}
	h := http.Header{}
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(k) == "" {
			continue
		}
		h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	return strings.ToUpper(parts[0]), parts[1], h, body
}

func (s *Server) regressionHTTPClient() (*http.Client, error) {
	tr := &http.Transport{
		MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
	}
	if addr := s.m.ProxyAddr(); addr != "" {
		pu := addr
		if !strings.Contains(pu, "://") {
			pu = "http://" + pu
		}
		u, err := url.Parse(pu)
		if err != nil {
			return nil, fmt.Errorf("出口代理解析失败: %w", err)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	if ca := s.m.ProxyCACert(); ca != "" {
		if pem, err := os.ReadFile(ca); err == nil {
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			if pool.AppendCertsFromPEM(pem) {
				tr.TLSClientConfig.RootCAs = pool
			}
		}
	}
	return &http.Client{
		Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}
