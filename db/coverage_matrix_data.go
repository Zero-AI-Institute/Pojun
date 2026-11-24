package db

import (
	"encoding/json"
	"strings"
)

// CoverageIntentRecord is one intent (current task + direct source tasks) with
// the asset anchors and yield count the coverage matrix needs.
type CoverageIntentRecord struct {
	ID            int64           `json:"id"`
	State         string          `json:"state"`
	Payload       json.RawMessage `json:"payload"`
	BlockedReason string          `json:"blocked_reason"`
	AssetIDs      []int64         `json:"asset_ids"`
	Yields        int             `json:"yields"`
}

// CoverageFindingRecord is one finding with its affected assets.
type CoverageFindingRecord struct {
	ID        int64   `json:"id"`
	Severity  string  `json:"severity"`
	Vulnclass string  `json:"vulnclass"`
	Name      string  `json:"name"`
	Summary   string  `json:"summary"`
	AssetIDs  []int64 `json:"asset_ids"`
}

// ScopeAssetsWithSources returns every asset in the current task's declared
// scope plus assets anchored by facts in the current/direct-source explorations.
// Tested marks assets already touched by a fact anchor.
func (s *AssetStore) ScopeAssetsWithSources(taskID int64) ([]CoverageAsset, error) {
	rows, err := s.db.Query(`WITH `+contextCoverageCTE+`
SELECT target.id, target.type, target.label,
       (target.id IN (SELECT asset_id FROM tested)) AS tested
FROM target
ORDER BY target.type, target.id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CoverageAsset{}
	for rows.Next() {
		var a CoverageAsset
		if err := rows.Scan(&a.ID, &a.Type, &a.Label, &a.Tested); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CoverageIntentsForTask returns intents from the current task and its direct
// source tasks, with their asset anchors and yields-edge count. Coverage is a
// read-only view; no rows are copied.
func (s *ExplorationStore) CoverageIntentsForTask(taskID int64) ([]CoverageIntentRecord, error) {
	rows, err := s.db.Query(`WITH `+directTaskContextCTE+`
SELECT n.id, n.state, n.payload, COALESCE(n.blocked_reason,'')
FROM exploration_nodes n
JOIN context_tasks ctx ON ctx.exploration_id=n.exploration_id
WHERE n.kind='intent' AND n.state <> 'deleted'
ORDER BY n.id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byID := map[int64]*CoverageIntentRecord{}
	out := []CoverageIntentRecord{}
	for rows.Next() {
		var r CoverageIntentRecord
		if err := rows.Scan(&r.ID, &r.State, &r.Payload, &r.BlockedReason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		byID[out[i].ID] = &out[i]
	}
	// Anchors
	arows, err := s.db.Query(`WITH `+directTaskContextCTE+`
SELECT ea.node_id, ea.asset_id
FROM exploration_anchors ea
JOIN exploration_nodes n ON n.id=ea.node_id
JOIN context_tasks ctx ON ctx.exploration_id=n.exploration_id
WHERE n.kind='intent' AND n.state <> 'deleted'`, taskID)
	if err != nil {
		return out, nil // anchors are optional; return nodes without them
	}
	for arows.Next() {
		var nodeID, assetID int64
		if err := arows.Scan(&nodeID, &assetID); err != nil {
			break
		}
		if r := byID[nodeID]; r != nil {
			r.AssetIDs = append(r.AssetIDs, assetID)
		}
	}
	arows.Close()
	// Yields
	yrows, err := s.db.Query(`WITH `+directTaskContextCTE+`
SELECT e.src_id, count(*)
FROM exploration_edges e
JOIN context_tasks ctx ON ctx.exploration_id=e.exploration_id
WHERE e.rel='yields'
GROUP BY e.src_id`, taskID)
	if err == nil {
		for yrows.Next() {
			var nodeID int64
			var n int
			if err := yrows.Scan(&nodeID, &n); err != nil {
				break
			}
			if r := byID[nodeID]; r != nil {
				r.Yields = n
			}
		}
		yrows.Close()
	}
	return out, nil
}

// CoverageFindingsForTask returns findings for the current task with parsed
// asset ids. asset_ids is JSONB; parsing errors degrade to no anchors.
func (s *ExplorationStore) CoverageFindingsForTask(taskID int64) ([]CoverageFindingRecord, error) {
	rows, err := s.db.Query(`SELECT id, COALESCE(severity,''), COALESCE(vulnclass,''),
       COALESCE(name,''), COALESCE(summary,''), asset_ids::text
FROM findings WHERE task_id=$1 ORDER BY id DESC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CoverageFindingRecord{}
	for rows.Next() {
		var r CoverageFindingRecord
		var idsText string
		if err := rows.Scan(&r.ID, &r.Severity, &r.Vulnclass, &r.Name, &r.Summary, &idsText); err != nil {
			return nil, err
		}
		idsText = strings.TrimSpace(idsText)
		if idsText != "" && idsText != "null" {
			_ = json.Unmarshal([]byte(idsText), &r.AssetIDs)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActivityStatsForIntent counts tool calls and errored steps for one intent.
// Used by the terminal reflection writer (deterministic, no LLM).
func (s *ExplorationStore) ActivityStatsForIntent(nodeID int64) (calls, errors int, err error) {
	err = s.db.QueryRow(`SELECT
  count(*) FILTER (WHERE tool <> ''),
  count(*) FILTER (WHERE is_error)
FROM activity WHERE exploration_id=$1 AND node_id=$2`, s.expID, nodeID).Scan(&calls, &errors)
	return
}
