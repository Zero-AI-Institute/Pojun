package agent

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/chu0119/pojun/db"
)

// CoverageCell is one asset-type × dimension aggregate in the coverage matrix.
type CoverageCell struct {
	AssetType string `json:"asset_type"`
	Dimension string `json:"dimension"`
	Total     int    `json:"total"`
	Untested  int    `json:"untested"`
	Open      int    `json:"open"`
	Running   int    `json:"running"`
	Done      int    `json:"done"`
	ZeroYield int    `json:"zero_yield"`
	Finding   int    `json:"finding"`
}

// CoverageDimensionSummary is per-dimension coverage across all asset types.
type CoverageDimensionSummary struct {
	Dimension string `json:"dimension"`
	Label     string `json:"label"`
	Total     int    `json:"total"`
	Untested  int    `json:"untested"`
	Open      int    `json:"open"`
	Running   int    `json:"running"`
	Done      int    `json:"done"`
	ZeroYield int    `json:"zero_yield"`
	Finding   int    `json:"finding"`
}

// CoverageGap is a ranked untested cell with sample assets.
type CoverageGap struct {
	Dimension string   `json:"dimension"`
	Label     string   `json:"label"`
	AssetType string   `json:"asset_type"`
	Untested  int      `json:"untested"`
	Samples   []string `json:"samples,omitempty"`
	Score     float64  `json:"score"`
}

// CoverageMatrix is the single source of truth for "what has been tested by
// asset × dimension" (v0.4.100). It is computed on demand, never persisted.
type CoverageMatrix struct {
	Assets         int                        `json:"assets"`
	Tested         int                        `json:"tested"`
	InProgress     int                        `json:"in_progress"`
	UntestedAssets int                        `json:"untested_assets"`
	Findings       int                        `json:"findings"`
	Cells          []CoverageCell             `json:"cells"`
	ByDimension    []CoverageDimensionSummary `json:"by_dimension"`
	TopGaps        []CoverageGap              `json:"top_gaps"`
}

var assetTypeWeight = map[string]float64{
	"service":     3,
	"endpoint":    3,
	"app":         2,
	"subdomain":   2,
	"root_domain": 1,
	"ip":          1,
}

var dimensionWeight = map[string]float64{
	dimAuthz:      3,
	dimInjection:  3,
	dimRCE:        3,
	dimUpload:     2,
	dimSSRF:       2,
	dimDataExport: 2,
	dimPayment:    2,
	dimCredReuse:  2,
	dimPrivesc:    1,
	dimLateral:    1,
	dimRecon:      1,
}

// BuildCoverageMatrix is pure (unit-testable): assets in scope, intents with
// anchors/yields, findings with assets → per-cell status counts + ranked gaps.
func BuildCoverageMatrix(assets []db.CoverageAsset, intents []db.CoverageIntentRecord, findings []db.CoverageFindingRecord) *CoverageMatrix {
	m := &CoverageMatrix{Assets: len(assets), Findings: len(findings)}
	if len(assets) == 0 {
		return m
	}
	assetByID := make(map[int64]db.CoverageAsset, len(assets))
	for _, a := range assets {
		assetByID[a.ID] = a
	}
	// intent payload view
	type intentView struct {
		rec       db.CoverageIntentRecord
		dimension string
		summary   string
	}
	intentsByAsset := map[int64][]intentView{}
	for _, it := range intents {
		var p struct {
			Dimension string `json:"dimension"`
			Summary   string `json:"summary"`
			Title     string `json:"title"`
		}
		_ = json.Unmarshal(it.Payload, &p)
		summary := p.Summary
		if summary == "" {
			summary = p.Title
		}
		v := intentView{rec: it, dimension: IntentDimension(p.Dimension, summary), summary: summary}
		if v.dimension == "" {
			v.dimension = dimOther
		}
		for _, aid := range it.AssetIDs {
			if _, ok := assetByID[aid]; ok {
				intentsByAsset[aid] = append(intentsByAsset[aid], v)
			}
		}
	}
	findingsByAsset := map[int64][]db.CoverageFindingRecord{}
	for _, f := range findings {
		for _, aid := range f.AssetIDs {
			if _, ok := assetByID[aid]; ok {
				findingsByAsset[aid] = append(findingsByAsset[aid], f)
			}
		}
	}

	type cellAgg struct {
		total, untested, open, running, done, zeroYield, finding int
	}
	cellMap := map[string]*cellAgg{}
	cellKey := func(typ, dim string) string { return typ + "\x00" + dim }
	untestedSamples := map[string][]string{}
	dimOrder := append(DimensionOrder(), dimOther)

	for _, a := range assets {
		ivs := intentsByAsset[a.ID]
		fvs := findingsByAsset[a.ID]
		terminal, active := false, false
		for _, iv := range ivs {
			switch iv.rec.State {
			case "running", "open", "paused":
				active = true
			case "done", "blocked", "exhausted", "stopped":
				terminal = true
			}
		}
		tested := a.Tested || len(fvs) > 0 || terminal
		if tested {
			m.Tested++
		} else if active {
			m.InProgress++
		} else {
			m.UntestedAssets++
		}
		// findings by dimension (unattributed -> other)
		findingDims := map[string]bool{}
		for _, f := range fvs {
			d := IntentDimension("", f.Vulnclass+" "+f.Name+" "+f.Summary)
			if d == "" {
				d = dimOther
			}
			findingDims[d] = true
		}
		// intents by dimension → best state
		intentDims := map[string]string{}
		for _, iv := range ivs {
			st := intentStateToCoverage(iv.rec.State, iv.rec.Yields)
			cur := intentDims[iv.dimension]
			if coverageStatusRank(st) > coverageStatusRank(cur) {
				intentDims[iv.dimension] = st
			}
		}
		for _, dim := range dimOrder {
			agg := cellMap[cellKey(a.Type, dim)]
			if agg == nil {
				agg = &cellAgg{}
				cellMap[cellKey(a.Type, dim)] = agg
			}
			agg.total++
			switch {
			case findingDims[dim]:
				agg.finding++
			case intentDims[dim] == "running":
				agg.running++
			case intentDims[dim] == "open":
				agg.open++
			case intentDims[dim] == "zero_yield":
				agg.zeroYield++
			case intentDims[dim] == "done":
				agg.done++
			default:
				agg.untested++
				if dim != dimOther && len(untestedSamples[cellKey(a.Type, dim)]) < 3 {
					untestedSamples[cellKey(a.Type, dim)] = append(untestedSamples[cellKey(a.Type, dim)], a.Label)
				}
			}
		}
	}

	// cells sorted deterministically
	types := map[string]bool{}
	for _, a := range assets {
		types[a.Type] = true
	}
	typeList := make([]string, 0, len(types))
	for t := range types {
		typeList = append(typeList, t)
	}
	sort.Strings(typeList)
	for _, typ := range typeList {
		for _, dim := range dimOrder {
			agg := cellMap[cellKey(typ, dim)]
			if agg == nil || agg.total == 0 {
				continue
			}
			m.Cells = append(m.Cells, CoverageCell{
				AssetType: typ, Dimension: dim, Total: agg.total, Untested: agg.untested,
				Open: agg.open, Running: agg.running, Done: agg.done,
				ZeroYield: agg.zeroYield, Finding: agg.finding,
			})
		}
	}

	// per-dimension summary
	for _, dim := range dimOrder {
		s := CoverageDimensionSummary{Dimension: dim, Label: DimensionLabel(dim), Total: len(assets)}
		for _, typ := range typeList {
			if agg := cellMap[cellKey(typ, dim)]; agg != nil {
				s.Untested += agg.untested
				s.Open += agg.open
				s.Running += agg.running
				s.Done += agg.done
				s.ZeroYield += agg.zeroYield
				s.Finding += agg.finding
			}
		}
		m.ByDimension = append(m.ByDimension, s)
	}

	// ranked gaps
	for _, typ := range typeList {
		for _, dim := range dimOrder {
			if dim == dimOther {
				continue
			}
			agg := cellMap[cellKey(typ, dim)]
			if agg == nil || agg.untested == 0 {
				continue
			}
			score := float64(agg.untested) * assetTypeWeight[typ] * dimensionWeight[dim]
			if score == 0 {
				score = float64(agg.untested)
			}
			m.TopGaps = append(m.TopGaps, CoverageGap{
				Dimension: dim, Label: DimensionLabel(dim), AssetType: typ,
				Untested: agg.untested, Samples: untestedSamples[cellKey(typ, dim)], Score: score,
			})
		}
	}
	sort.SliceStable(m.TopGaps, func(i, j int) bool {
		if m.TopGaps[i].Score != m.TopGaps[j].Score {
			return m.TopGaps[i].Score > m.TopGaps[j].Score
		}
		if m.TopGaps[i].Untested != m.TopGaps[j].Untested {
			return m.TopGaps[i].Untested > m.TopGaps[j].Untested
		}
		return m.TopGaps[i].Dimension < m.TopGaps[j].Dimension
	})
	if len(m.TopGaps) > 8 {
		m.TopGaps = m.TopGaps[:8]
	}
	return m
}

func intentStateToCoverage(state string, yields int) string {
	switch state {
	case "running":
		return "running"
	case "open", "paused":
		return "open"
	case "done", "blocked", "exhausted", "stopped":
		if yields > 0 {
			return "done"
		}
		return "zero_yield"
	}
	return ""
}

func coverageStatusRank(s string) int {
	switch s {
	case "running":
		return 5
	case "open":
		return 4
	case "zero_yield":
		return 3
	case "done":
		return 2
	}
	return 0
}

// CoverageMatrixForTask fetches and builds the matrix. Any data-source failure
// returns nil (fail open: coverage is advisory, never blocks the task).
func CoverageMatrixForTask(as *db.AssetStore, ts *db.ExplorationStore, taskID int64) *CoverageMatrix {
	if as == nil || ts == nil || taskID <= 0 {
		return nil
	}
	assets, err := as.ScopeAssetsWithSources(taskID)
	if err != nil {
		return nil
	}
	intents, err := ts.CoverageIntentsForTask(taskID)
	if err != nil {
		return nil
	}
	findings, err := ts.CoverageFindingsForTask(taskID)
	if err != nil {
		findings = nil
	}
	return BuildCoverageMatrix(assets, intents, findings)
}

// coverageMatrix is the ToolSet-bound convenience wrapper.
func (t *ToolSet) coverageMatrix() *CoverageMatrix {
	if t == nil || t.as == nil || t.ts == nil || t.taskID <= 0 {
		return nil
	}
	return CoverageMatrixForTask(t.as, t.ts, t.taskID)
}

// compactReflections renders lessons for prompt injection.
func compactReflections(rs []db.IntentReflection) []map[string]any {
	out := make([]map[string]any, 0, len(rs))
	for _, r := range rs {
		m := map[string]any{
			"intent_id": r.IntentID,
			"dimension": r.Dimension,
			"state":     r.TerminalState,
			"reason":    r.TerminalReason,
			"wrote":     r.WroteBack,
			"calls":     r.ToolCalls,
			"errors":    r.ToolErrors,
			"lesson":    r.Lesson,
		}
		if strings.TrimSpace(r.Summary) != "" {
			m["summary"] = firstLine(r.Summary, 100)
		}
		out = append(out, m)
	}
	return out
}
