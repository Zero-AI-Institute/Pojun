package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
)

func TestProgramProfileBlock(t *testing.T) {
	if got := ProgramProfileBlock(nil); got != "" {
		t.Fatalf("nil profile must render empty, got %q", got)
	}
	if got := ProgramProfileBlock(&db.ProgramProfile{}); got != "" {
		t.Fatalf("empty profile must render empty, got %q", got)
	}
	p := &db.ProgramProfile{
		Platform: "hackerone", Handle: "acme", RPS: 2, DryRun: true, AllowRace: true,
		Scope: []string{"example.com"}, Excluded: []string{"admin.example.com"},
		ScannersAllowed: []string{"nuclei"},
		AllowedHosts:    []string{"*.example.com"}, DeniedHosts: []string{"admin.example.com"},
		WindowStart: "09:00", WindowEnd: "18:00", Timezone: "Asia/Shanghai", MaxConcurrent: 4,
	}
	got := ProgramProfileBlock(p)
	for _, want := range []string{"hackerone", "acme", "2.00 req/s", "dry-run", "admin.example.com", "nuclei", "allowlist", "09:00-18:00", "并发上限：4"} {
		if !strings.Contains(got, want) {
			t.Errorf("block missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "永久") {
		t.Errorf("unexpected wording: %s", got)
	}
}

func TestProgramProfileHeaderInjected(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Bug-Bounty")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "test")
	ts.SetTaskID(1)
	ts.SetProgramProfile(&db.ProgramProfile{Handle: "acme"})
	out := ts.doHTTP(context.Background(), httpArgs{URL: srv.URL}, nil)
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if got != "acme" {
		t.Fatalf("X-Bug-Bounty = %q, want acme", got)
	}
	// 显式 header 优先，不被 profile 覆盖。
	got = ""
	out = ts.doHTTP(context.Background(), httpArgs{URL: srv.URL, Headers: "X-Bug-Bounty: explicit"}, nil)
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if got != "explicit" {
		t.Fatalf("explicit header = %q", got)
	}
}

func TestProgramProfileDryRunBlocksWrites(t *testing.T) {
	ts := NewToolSet(nil, "test")
	ts.SetTaskID(1)
	ts.SetProgramProfile(&db.ProgramProfile{DryRun: true})
	tool := ts.httpRequest()
	res, err := tool.Call(context.Background(), json.RawMessage(`{"url":"http://127.0.0.1:1/x","method":"POST"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Flatten(), "dry-run") {
		t.Fatalf("POST should be blocked: %q", res.Flatten())
	}
	// GET 不在 dry-run 拦截范围（会真的发请求，这里只验证未被 dry-run 文案拦下）。
	res, err = tool.Call(context.Background(), json.RawMessage(`{"url":"http://127.0.0.1:1/x","method":"GET"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Flatten(), "dry-run 模式禁止") {
		t.Fatalf("GET should not be dry-run blocked: %q", res.Flatten())
	}
}

func TestProgramProfileClearedBySetTaskID(t *testing.T) {
	ts := NewToolSet(nil, "test")
	ts.SetProgramProfile(&db.ProgramProfile{RPS: 10})
	ts.SetTaskID(123)
	ts.SetProgramProfile(nil)
	// 清空后不应有残留限速：连续 wait 应瞬时返回（用 rps=0 的行为验证）。
	ConfigureProgramRPS(123, 0)
	if err := waitProgramRPS(context.Background(), 123); err != nil {
		t.Fatal(err)
	}
}

func TestProgramRPSWaitRespectsContext(t *testing.T) {
	const taskID = int64(424242)
	ConfigureProgramRPS(taskID, 0.01) // 100s/token
	t.Cleanup(func() { ConfigureProgramRPS(taskID, 0) })
	if err := waitProgramRPS(context.Background(), taskID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := waitProgramRPS(ctx, taskID); err == nil {
		t.Fatal("second token should wait and hit context deadline")
	}
}
