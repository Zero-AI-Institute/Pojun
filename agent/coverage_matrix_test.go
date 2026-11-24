package agent

import (
	"encoding/json"
	"testing"

	"github.com/chu0119/pojun/db"
)

func mustPayload(v map[string]any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func TestBuildCoverageMatrix(t *testing.T) {
	assets := []db.CoverageAsset{
		{ID: 1, Type: "service", Label: "https://a.example.com"},
		{ID: 2, Type: "endpoint", Label: "https://a.example.com/api/user?id=1"},
		{ID: 3, Type: "subdomain", Label: "api.example.com"},
		{ID: 4, Type: "ip", Label: "10.0.0.1"},
	}
	intents := []db.CoverageIntentRecord{
		{ID: 11, State: "done", Payload: mustPayload(map[string]any{"summary": "authz test", "dimension": "authz"}), AssetIDs: []int64{1}, Yields: 2},
		{ID: 12, State: "exhausted", Payload: mustPayload(map[string]any{"summary": "sqli test"}), AssetIDs: []int64{2}, Yields: 0},
		{ID: 13, State: "running", Payload: mustPayload(map[string]any{"summary": "sql injection again"}), AssetIDs: []int64{2}, Yields: 0},
		{ID: 14, State: "open", Payload: mustPayload(map[string]any{"summary": "upload probe", "dimension": "upload"}), AssetIDs: []int64{3}, Yields: 0},
	}
	findings := []db.CoverageFindingRecord{
		{ID: 21, Severity: "high", Vulnclass: "IDOR", Summary: "horizontal idor", AssetIDs: []int64{2}},
	}
	m := BuildCoverageMatrix(assets, intents, findings)
	if m.Assets != 4 || m.Tested != 2 || m.InProgress != 1 || m.UntestedAssets != 1 || m.Findings != 1 {
		t.Fatalf("summary = assets=%d tested=%d in_progress=%d untested=%d findings=%d",
			m.Assets, m.Tested, m.InProgress, m.UntestedAssets, m.Findings)
	}
	cell := func(typ, dim string) CoverageCell {
		for _, c := range m.Cells {
			if c.AssetType == typ && c.Dimension == dim {
				return c
			}
		}
		return CoverageCell{}
	}
	if c := cell("service", "authz"); c.Done != 1 || c.Total != 1 {
		t.Fatalf("service/authz = %+v", c)
	}
	// endpoint/injection: running wins over exhausted zero-yield
	if c := cell("endpoint", "injection"); c.Running != 1 || c.ZeroYield != 0 {
		t.Fatalf("endpoint/injection = %+v", c)
	}
	// finding inferred as authz and takes priority
	if c := cell("endpoint", "authz"); c.Finding != 1 {
		t.Fatalf("endpoint/authz = %+v", c)
	}
	if c := cell("subdomain", "upload"); c.Open != 1 {
		t.Fatalf("subdomain/upload = %+v", c)
	}
	// ip has no intent/finding → untested in every dimension (it may fall outside
	// the top-8 gap window because its asset-type weight is low).
	if c := cell("ip", "authz"); c.Untested != 1 {
		t.Fatalf("ip/authz = %+v", c)
	}
	if len(m.TopGaps) == 0 {
		t.Fatal("top gaps empty")
	}
}

func TestBuildCoverageMatrixEmpty(t *testing.T) {
	m := BuildCoverageMatrix(nil, nil, nil)
	if m == nil || m.Assets != 0 || len(m.Cells) != 0 {
		t.Fatalf("empty matrix = %+v", m)
	}
}

func TestIntentDimensionExport(t *testing.T) {
	if got := IntentDimension("", "sql injection on /api"); got != dimInjection {
		t.Fatalf("infer = %q", got)
	}
	if got := IntentDimension("idor", "whatever"); got != dimAuthz {
		t.Fatalf("explicit = %q", got)
	}
	if DimensionLabel(dimAuthz) == "" || DimensionTip(dimAuthz) == "" {
		t.Fatal("label/tip empty")
	}
}
