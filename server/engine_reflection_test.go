package server

import (
	"strings"
	"testing"

	"github.com/chu0119/pojun/agent"
)

func TestBuildReflectionLesson(t *testing.T) {
	done := buildReflectionLesson("done", "", "test authz", "read one record",
		agent.WriteCounts{Facts: 1, Findings: 1, Assets: 2}, 7, 1)
	for _, want := range []string{"完成且有写回", "事实1", "漏洞1", "工具7次", "验收标准"} {
		if !strings.Contains(done, want) {
			t.Fatalf("done lesson missing %q: %s", want, done)
		}
	}
	ex := buildReflectionLesson("exhausted", "max_turns", "sqli probe", "",
		agent.WriteCounts{}, 12, 3)
	if !strings.Contains(ex, "耗尽无产出") || !strings.Contains(ex, "max_turns") {
		t.Fatalf("exhausted lesson: %s", ex)
	}
	bl := buildReflectionLesson("blocked", "error: connection refused", "upload probe", "",
		agent.WriteCounts{}, 2, 2)
	if !strings.Contains(bl, "阻塞") || !strings.Contains(bl, "error") {
		t.Fatalf("blocked lesson: %s", bl)
	}
}

func TestCoverageReportRows(t *testing.T) {
	// guards the shape the DOCX/Markdown renderers rely on
	rows := []string{agent.DimensionLabel(agent.DimensionOrder()[0])}
	if rows[0] == "" {
		t.Fatal("dimension label empty")
	}
}
