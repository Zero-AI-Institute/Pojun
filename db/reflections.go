package db

import (
	"encoding/json"
	"strings"
	"time"
)

// IntentReflection is a deterministic lesson recorded when an intent reaches a
// terminal state. It is written by the engine (no LLM) and read by the planner
// and worker so a failed/zero-yield direction is not repeated blindly.
type IntentReflection struct {
	ID              int64           `json:"id"`
	IntentID        int64           `json:"intent_id"`
	Dimension       string          `json:"dimension"`
	TerminalState   string          `json:"terminal_state"`
	TerminalReason  string          `json:"terminal_reason"`
	WroteBack       int             `json:"wrote_back"`
	ToolCalls       int             `json:"tool_calls"`
	ToolErrors      int             `json:"tool_errors"`
	Success         bool            `json:"success"`
	Hypothesis      string          `json:"hypothesis,omitempty"`
	SuccessCriteria string          `json:"success_criteria,omitempty"`
	Summary         string          `json:"summary"`
	Lesson          string          `json:"lesson"`
	AssetIDs        []int64         `json:"asset_ids,omitempty"`
	Payload         json.RawMessage `json:"payload,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
}

// RecordIntentReflection upserts the lesson for one intent (terminal writes can
// be retried; only the latest deterministic snapshot matters).
func (s *ExplorationStore) RecordIntentReflection(r IntentReflection) error {
	assetIDs, _ := json.Marshal(r.AssetIDs)
	if len(assetIDs) == 0 || string(assetIDs) == "null" {
		assetIDs = []byte("[]")
	}
	payload := r.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	_, err := s.db.Exec(`
INSERT INTO intent_reflections(
  exploration_id, intent_id, dimension, terminal_state, terminal_reason,
  wrote_back, tool_calls, tool_errors, success, hypothesis, success_criteria,
  summary, lesson, asset_ids, payload)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT (intent_id) DO UPDATE SET
  dimension=EXCLUDED.dimension,
  terminal_state=EXCLUDED.terminal_state,
  terminal_reason=EXCLUDED.terminal_reason,
  wrote_back=EXCLUDED.wrote_back,
  tool_calls=EXCLUDED.tool_calls,
  tool_errors=EXCLUDED.tool_errors,
  success=EXCLUDED.success,
  hypothesis=EXCLUDED.hypothesis,
  success_criteria=EXCLUDED.success_criteria,
  summary=EXCLUDED.summary,
  lesson=EXCLUDED.lesson,
  asset_ids=EXCLUDED.asset_ids,
  payload=EXCLUDED.payload,
  created_at=now()`,
		s.expID, r.IntentID, r.Dimension, r.TerminalState, r.TerminalReason,
		r.WroteBack, r.ToolCalls, r.ToolErrors, r.Success, r.Hypothesis, r.SuccessCriteria,
		r.Summary, r.Lesson, string(assetIDs), string(payload))
	return err
}

func (s *ExplorationStore) scanReflections(query string, args ...any) ([]IntentReflection, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IntentReflection{}
	for rows.Next() {
		var r IntentReflection
		var idsText string
		var payload []byte
		if err := rows.Scan(&r.ID, &r.IntentID, &r.Dimension, &r.TerminalState, &r.TerminalReason,
			&r.WroteBack, &r.ToolCalls, &r.ToolErrors, &r.Success,
			&r.Hypothesis, &r.SuccessCriteria, &r.Summary, &r.Lesson,
			&idsText, &payload, &r.CreatedAt); err != nil {
			return nil, err
		}
		if strings.TrimSpace(idsText) != "" && idsText != "null" {
			_ = json.Unmarshal([]byte(idsText), &r.AssetIDs)
		}
		r.Payload = append(json.RawMessage(nil), payload...)
		out = append(out, r)
	}
	return out, rows.Err()
}

const reflectionCols = `id, intent_id, dimension, terminal_state, terminal_reason,
  wrote_back, tool_calls, tool_errors, success, hypothesis, success_criteria,
  summary, lesson, asset_ids::text, payload, created_at`

// RecentReflections returns the newest lessons for this exploration.
func (s *ExplorationStore) RecentReflections(limit int) ([]IntentReflection, error) {
	if limit <= 0 {
		limit = 10
	}
	return s.scanReflections(`SELECT `+reflectionCols+`
FROM intent_reflections WHERE exploration_id=$1 ORDER BY id DESC LIMIT $2`, s.expID, limit)
}

// ReflectionsForDimension returns newest lessons for one dimension.
func (s *ExplorationStore) ReflectionsForDimension(dimension string, limit int) ([]IntentReflection, error) {
	if limit <= 0 {
		limit = 10
	}
	return s.scanReflections(`SELECT `+reflectionCols+`
FROM intent_reflections WHERE exploration_id=$1 AND dimension=$2 ORDER BY id DESC LIMIT $3`,
		s.expID, dimension, limit)
}
