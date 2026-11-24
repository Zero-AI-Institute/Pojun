package db

import (
	"context"
	"testing"
)

// v0.4.102: audit_finding depends on ExplorationStore.Finding enforcing
// task/exploration scope. A finding from another task must not be readable.
func TestExplorationFindingScope(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	t1, err := d.CreateTask("auditor scope 1", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t2, err := d.CreateTask("auditor scope 2", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	st1 := d.Exploration(t1.ExplorationID)
	rec, err := st1.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: t1.ID, ExplorationID: t1.ExplorationID,
		VulnClass: "注入", Name: "scope test", Severity: "high",
		Summary: "scope test", Evidence: "GET /x?id=1 -> 200", VerificationStrategy: "http_diff",
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := st1.Finding(rec.FindingID)
	if err != nil || f == nil {
		t.Fatalf("own finding: f=%v err=%v", f, err)
	}
	if f.TaskID == nil || *f.TaskID != t1.ID {
		t.Fatalf("task id = %v", f.TaskID)
	}
	st2 := d.Exploration(t2.ExplorationID)
	if f2, err := st2.Finding(rec.FindingID); err != nil || f2 != nil {
		t.Fatalf("cross-task finding must be nil: f=%v err=%v", f2, err)
	}
}
