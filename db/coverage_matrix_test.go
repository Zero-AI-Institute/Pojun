package db

import (
	"context"
	"testing"
)

// v0.4.100: coverage matrix data path — scope assets, intent anchors/yields,
// findings with asset ids. Exercises the SQL CTEs used by planner/nudge/report.
func TestCoverageMatrixData(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	task, err := d.CreateTask("coverage matrix data", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	as := d.Assets()
	if _, err := as.UpsertRootDomain(UpsertRootDomainReq{Domain: "cov.example.com", TaskID: task.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := as.AddAgentScope(task.ID, "root_domain", "cov.example.com", "test", "agent"); err != nil {
		t.Fatal(err)
	}
	svcID, err := as.UpsertHTTPService(UpsertHTTPServiceReq{URL: "https://api.cov.example.com", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	epID, err := as.UpsertEndpoint(UpsertEndpointReq{URL: "https://api.cov.example.com/api/user?id=1", Method: "GET", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	st := d.Exploration(task.ExplorationID)
	intentID, err := st.AddIntent(map[string]any{"summary": "authz test", "dimension": "authz"}, 5, []int64{svcID}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodeState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	factID, err := st.AddNode(KindFact, map[string]any{"summary": "authz tested"}, 0, "confirmed", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Link(intentID, RelYields, factID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordFinding(context.Background(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID,
		VulnClass: "IDOR", Name: "IDOR", Severity: "high", Summary: "idor", AssetIDs: []int64{epID},
	}); err != nil {
		t.Fatal(err)
	}

	assets, err := as.ScopeAssetsWithSources(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) < 3 {
		t.Fatalf("scope assets = %d, want >=3: %+v", len(assets), assets)
	}
	intents, err := st.CoverageIntentsForTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 1 || len(intents[0].AssetIDs) != 1 || intents[0].AssetIDs[0] != svcID || intents[0].Yields != 1 {
		t.Fatalf("intents = %+v", intents)
	}
	findings, err := st.CoverageFindingsForTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || len(findings[0].AssetIDs) != 1 || findings[0].AssetIDs[0] != epID {
		t.Fatalf("findings = %+v", findings)
	}
}
