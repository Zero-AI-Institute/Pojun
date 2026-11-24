package agent

import (
	"os"
	"strings"
	"testing"

	"github.com/chu0119/pojun/db"
)

func TestRenderToolRoutingStats(t *testing.T) {
	if got := renderToolRoutingStats("recon", nil, nil); got != "" {
		t.Fatalf("empty stats should render empty, got %q", got)
	}
	got := renderToolRoutingStats("recon",
		[]db.ToolOutcomeStat{
			{Tool: "http_request", Uses: 5, Errors: 0},
			{Tool: "Bash", Uses: 10, Errors: 2},
		},
		[]db.ToolOutcomeStat{{Tool: "nmap", Uses: 10, Errors: 7}},
	)
	for _, want := range []string{"侦察/枚举", "http_request：5 次 / 错误 0（0%）", "Bash：10 次 / 错误 2（20%）", "历史高错误率", "nmap：10 次 / 错误 7（70%）", "未列出的工具不代表不能用"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
}

func TestToolRoutingBlock(t *testing.T) {
	dsn := os.Getenv("POJUN_PG_DSN")
	if dsn == "" {
		t.Skip("POJUN_PG_DSN not set")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()
	task, err := d.CreateTask("routing fixture", "g", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	es := d.Exploration(task.ExplorationID)
	intent, err := es.AddNode(db.KindIntent, map[string]any{"summary": "recon"}, 0, "done", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.RecordIntentReflection(db.IntentReflection{IntentID: intent, Dimension: "recon", TerminalState: "done"}); err != nil {
		t.Fatal(err)
	}
	insert := func(tool, kind string, isErr bool) {
		if _, err := d.Exec(`INSERT INTO activity(exploration_id,node_id,worker,kind,tool,is_error)
VALUES ($1,$2,'worker',$3,$4,$5)`, task.ExplorationID, intent, kind, tool, isErr); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 10; i++ {
		insert("Bash", "tool_use", false)
	}
	for i := 0; i < 2; i++ {
		insert("Bash", "tool_result", true)
	}
	for i := 0; i < 5; i++ {
		insert("http_request", "tool_use", false)
	}
	for i := 0; i < 10; i++ {
		insert("nmap", "tool_use", false)
	}
	for i := 0; i < 7; i++ {
		insert("nmap", "tool_result", true)
	}
	block := toolRoutingBlock(es, &db.Node{Payload: []byte(`{"dimension":"recon","summary":"recon"}`)}, 5)
	if !strings.Contains(block, "http_request") || !strings.Contains(block, "Bash") {
		t.Fatalf("routing block missing stats:\n%s", block)
	}
	// 样本不足（同维度只有 1 个工具）时不注入，避免噪声。
	if got := toolRoutingBlock(es, &db.Node{Payload: []byte(`{"dimension":"authz"}`)}, 5); got != "" {
		t.Fatalf("sparse dimension should not inject: %q", got)
	}
}
