package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chu0119/pojun/db"
)

func TestHostMatchesPattern(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"a.example.com", "*.example.com", true},
		{"example.com", "*.example.com", false},
		{"evil-example.com", "*.example.com", false},
		{"a.example.com", "example.com", false},
	}
	for _, c := range cases {
		if got := hostMatchesPattern(c.host, c.pattern); got != c.want {
			t.Errorf("%s vs %s = %v, want %v", c.host, c.pattern, got, c.want)
		}
	}
}

func TestInTimeWindow(t *testing.T) {
	day := func(h, m int) time.Time { return time.Date(2026, 11, 24, h, m, 0, 0, time.UTC) }
	if !inTimeWindow(day(10, 0), "09:00", "18:00") {
		t.Fatal("10:00 should be inside 09-18")
	}
	if inTimeWindow(day(18, 0), "09:00", "18:00") {
		t.Fatal("end is exclusive")
	}
	if !inTimeWindow(day(23, 0), "22:00", "06:00") {
		t.Fatal("overnight window should include 23:00")
	}
	if !inTimeWindow(day(5, 0), "22:00", "06:00") {
		t.Fatal("overnight window should include 05:00")
	}
	if inTimeWindow(day(12, 0), "22:00", "06:00") {
		t.Fatal("12:00 should be outside overnight window")
	}
	if !inTimeWindow(day(12, 0), "09:00", "09:00") {
		t.Fatal("start==end should mean all-day")
	}
}

func TestCheckProgramEgress(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, loc)
	allowed := []string{"*.example.com", "api.example.org"}
	denied := []string{"admin.example.com"}

	if err := checkProgramEgress("app.example.com", now, allowed, denied, "09:00", "18:00", loc); err != nil {
		t.Fatalf("allowed host rejected: %v", err)
	}
	if err := checkProgramEgress("other.com", now, allowed, denied, "", "", loc); err == nil {
		t.Fatal("host outside allowlist should be rejected")
	}
	if err := checkProgramEgress("admin.example.com", now, allowed, denied, "", "", loc); err == nil {
		t.Fatal("denylist must win")
	}
	if err := checkProgramEgress("app.example.com", time.Date(2026, 11, 24, 20, 0, 0, 0, loc), allowed, denied, "09:00", "18:00", loc); err == nil {
		t.Fatal("outside window should be rejected")
	}
	if err := checkProgramEgress("app.example.com", now, nil, nil, "", "", loc); err != nil {
		t.Fatalf("empty policy should allow: %v", err)
	}
}

func TestDoHTTPDeniedHostDoesNotDial(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	ts := NewToolSet(nil, "test")
	ts.SetTaskID(7)
	ts.SetProgramProfile(&db.ProgramProfile{DeniedHosts: []string{"127.0.0.1"}})
	out := ts.doHTTP(context.Background(), httpArgs{URL: srv.URL}, nil)
	if out.Err == nil || !strings.Contains(out.Err.Error(), "denylist") {
		t.Fatalf("expected denylist error, got %v", out.Err)
	}
	if hit {
		t.Fatal("denied request must not reach the target")
	}
}

func TestProgramConcurrencySlot(t *testing.T) {
	const taskID = int64(424243)
	release, err := acquireProgramSlot(context.Background(), taskID, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := acquireProgramSlot(ctx, taskID, 1); err == nil {
		t.Fatal("second slot should wait and hit context deadline")
	}
	release()
	release2, err := acquireProgramSlot(context.Background(), taskID, 1)
	if err != nil {
		t.Fatal(err)
	}
	release2()
}

func TestDoHTTPRedirectCannotBypassDenylist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+strings.TrimPrefix(r.Host, "127.0.0.1:")+"/final", http.StatusFound)
	}))
	defer srv.Close()
	ts := NewToolSet(nil, "test")
	ts.SetTaskID(8)
	ts.SetProgramProfile(&db.ProgramProfile{
		AllowedHosts: []string{"127.0.0.1"},
		DeniedHosts:  []string{"localhost"},
	})
	out := ts.doHTTP(context.Background(), httpArgs{URL: srv.URL}, nil)
	if out.Err == nil || !strings.Contains(out.Err.Error(), "denylist") {
		t.Fatalf("redirect should be blocked by denylist, got %v", out.Err)
	}
}
