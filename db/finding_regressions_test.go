package db

import (
	"context"
	"database/sql"
	"testing"
)

func TestFindingRegressionUpsertAndRead(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()
	task, err := d.CreateTask("regression fixture", "g", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	var findingID int64
	if err := d.QueryRow(`INSERT INTO findings(task_id,vulnclass,name,severity,summary,evidence,status,asset_ids)
VALUES($1,'XSS','xss','high','s','validate:abcdefgh1234:pass','pending','[]') RETURNING id`, task.ID).Scan(&findingID); err != nil {
		t.Fatal(err)
	}
	prepared := []PreparedTrafficEvidence{
		{Ref: TrafficRef{TrafficID: "base-1", Role: "baseline"}, Snapshot: TrafficEvidenceSnapshot{URL: "http://example.com/x", Method: "GET", Status: 200}},
		{Ref: TrafficRef{TrafficID: "proof-1", Role: "proof"}, Snapshot: TrafficEvidenceSnapshot{URL: "http://example.com/x", Method: "GET", Status: 200}},
	}
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := UpsertFindingRegressionTx(tx, findingID, RecordFindingInput{TaskID: task.ID, VulnClass: "XSS", Evidence: "validate:abcdefgh1234:pass"}, prepared); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	r, err := d.GetFindingRegression(findingID)
	if err != nil || r == nil {
		t.Fatalf("regression = %+v, %v", r, err)
	}
	if r.Assertion != "token" || r.Token != "abcdefgh1234" || r.ProofTrafficID != "proof-1" || r.BaselineTrafficID != "base-1" {
		t.Fatalf("spec = %+v", r)
	}
	if err := d.RecordFindingRegressionResult(findingID, "pass", "ok"); err != nil {
		t.Fatal(err)
	}
	r, _ = d.GetFindingRegression(findingID)
	if r.LastVerdict != "pass" || r.LastCheckedAt == nil {
		t.Fatalf("result = %+v", r)
	}
	// 无 proof 流量不生成 spec。
	if err := UpsertFindingRegressionTx(mustTx(t, d), findingID, RecordFindingInput{}, nil); err != nil {
		t.Fatal(err)
	}
	list, err := d.ListFindingRegressions(task.ID, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	_ = context.Background()
}

func mustTx(t *testing.T, d *DB) *sql.Tx {
	t.Helper()
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	return tx
}
