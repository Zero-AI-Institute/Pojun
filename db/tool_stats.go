package db

// P2-1 工具路由学习：按「意图维度 × 工具 × 结果」聚合本任务的历史工具表现。
// 数据来自 activity（tool_use / tool_result.is_error）与 intent_reflections
// （终态意图的 dimension）。只做只读聚合，不改变工具选择或拦截。

type ToolOutcomeStat struct {
	Tool   string `json:"tool"`
	Uses   int    `json:"uses"`
	Errors int    `json:"errors"`
}

// ToolOutcomeStats returns the most reliable tools used by terminal intents in
// one dimension, ordered by error ratio ascending then usage descending. Tools
// with fewer than 3 tool_use rows are ignored (too little signal).
func (s *ExplorationStore) ToolOutcomeStats(dimension string, limit int) ([]ToolOutcomeStat, error) {
	if s == nil || dimension == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 5
	}
	if limit > 10 {
		limit = 10
	}
	rows, err := s.db.Query(`
SELECT a.tool,
       COUNT(*) FILTER (WHERE a.kind='tool_use') AS uses,
       COUNT(*) FILTER (WHERE a.kind='tool_result' AND a.is_error) AS errors
FROM activity a
JOIN intent_reflections r ON r.intent_id = a.node_id
WHERE r.exploration_id=$1 AND r.dimension=$2
  AND a.tool IS NOT NULL AND a.tool <> ''
GROUP BY a.tool
HAVING COUNT(*) FILTER (WHERE a.kind='tool_use') >= 3
ORDER BY (COUNT(*) FILTER (WHERE a.kind='tool_result' AND a.is_error)::float
          / NULLIF(COUNT(*) FILTER (WHERE a.kind='tool_use'),0)) ASC,
         uses DESC
LIMIT $3`, s.expID, dimension, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ToolOutcomeStat, 0, limit)
	for rows.Next() {
		var st ToolOutcomeStat
		if err := rows.Scan(&st.Tool, &st.Uses, &st.Errors); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// HighErrorTools returns tools in one dimension whose historical error ratio is
// at least minRatio over minUses calls, worst first. Used by the worker prompt
// to flag "this approach keeps failing" — advisory only, never blocks a tool.
func (s *ExplorationStore) HighErrorTools(dimension string, minUses int, minRatio float64, limit int) ([]ToolOutcomeStat, error) {
	if s == nil || dimension == "" {
		return nil, nil
	}
	if minUses <= 0 {
		minUses = 5
	}
	if minRatio < 0 || minRatio > 1 {
		minRatio = 0.6
	}
	if limit <= 0 {
		limit = 3
	}
	if limit > 5 {
		limit = 5
	}
	rows, err := s.db.Query(`
SELECT a.tool,
       COUNT(*) FILTER (WHERE a.kind='tool_use') AS uses,
       COUNT(*) FILTER (WHERE a.kind='tool_result' AND a.is_error) AS errors
FROM activity a
JOIN intent_reflections r ON r.intent_id = a.node_id
WHERE r.exploration_id=$1 AND r.dimension=$2
  AND a.tool IS NOT NULL AND a.tool <> ''
GROUP BY a.tool
HAVING COUNT(*) FILTER (WHERE a.kind='tool_use') >= $3
   AND (COUNT(*) FILTER (WHERE a.kind='tool_result' AND a.is_error)::float
        / NULLIF(COUNT(*) FILTER (WHERE a.kind='tool_use'),0)) >= $4
ORDER BY (COUNT(*) FILTER (WHERE a.kind='tool_result' AND a.is_error)::float
          / NULLIF(COUNT(*) FILTER (WHERE a.kind='tool_use'),0)) DESC,
         uses DESC
LIMIT $5`, s.expID, dimension, minUses, minRatio, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ToolOutcomeStat, 0, limit)
	for rows.Next() {
		var st ToolOutcomeStat
		if err := rows.Scan(&st.Tool, &st.Uses, &st.Errors); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}
