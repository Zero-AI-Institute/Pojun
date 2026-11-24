package db

// 确定性回归库（v0.4.119 / P2-7）。
//
// 只对“有 proof/verification 流量 + 可判定断言”的 finding 生成 spec。请求头/正文
// 不落库（可能含 Cookie/凭据），检查时按 traffic_id 从流量库取；流量被清理后
// 返回 not_replayable，而不是用过期配置猜。

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"
)

type FindingRegression struct {
	ID                int64      `json:"id,string"`
	FindingID         int64      `json:"finding_id,string"`
	TaskID            int64      `json:"task_id,string,omitempty"`
	VulnClass         string     `json:"vulnclass"`
	BaselineTrafficID string     `json:"baseline_traffic_id,omitempty"`
	ProofTrafficID    string     `json:"proof_traffic_id"`
	Method            string     `json:"method"`
	URL               string     `json:"url"`
	Assertion         string     `json:"assertion"`
	ExpectedStatus    int        `json:"expected_status"`
	Token             string     `json:"token,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	LastCheckedAt     *time.Time `json:"last_checked_at,omitempty"`
	LastVerdict       string     `json:"last_verdict,omitempty"`
	LastNote          string     `json:"last_note,omitempty"`
}

var regressionTokenRe = regexp.MustCompile(`validate:([A-Za-z0-9_-]{8,128}):pass`)

// UpsertFindingRegressionTx creates/refreshes the spec for one finding. It is
// called inside the same transaction as finding/traffic insertion, so a
// committed finding always has its regression row if it is replayable.
func UpsertFindingRegressionTx(tx *sql.Tx, findingID int64, in RecordFindingInput, prepared []PreparedTrafficEvidence) error {
	if tx == nil || findingID <= 0 || len(prepared) == 0 {
		return nil
	}
	var baseline, proof *PreparedTrafficEvidence
	for i := range prepared {
		switch prepared[i].Ref.Role {
		case "proof", "verification":
			if proof == nil {
				proof = &prepared[i]
			}
		case "baseline":
			if baseline == nil {
				baseline = &prepared[i]
			}
		}
	}
	if proof == nil || strings.TrimSpace(proof.Snapshot.URL) == "" {
		return nil // 没有可回放的 proof 流量：不生成假 spec
	}
	assertion := "status"
	token := ""
	if m := regressionTokenRe.FindStringSubmatch(in.Evidence); len(m) == 2 {
		assertion, token = "token", m[1]
	} else if baseline != nil && (in.VerificationStrategy == "http_diff" || in.VerificationStrategy == "dual_identity") {
		assertion = "diff"
	}
	method := strings.ToUpper(strings.TrimSpace(proof.Snapshot.Method))
	if method == "" {
		method = "GET"
	}
	baselineID := ""
	if baseline != nil {
		baselineID = baseline.Ref.TrafficID
	}
	_, err := tx.Exec(`
INSERT INTO finding_regressions(
  finding_id, task_id, vulnclass, baseline_traffic_id, proof_traffic_id,
  method, url, assertion, expected_status, token)
VALUES($1,NULLIF($2,0),$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT(finding_id) DO UPDATE SET
  task_id=EXCLUDED.task_id, vulnclass=EXCLUDED.vulnclass,
  baseline_traffic_id=EXCLUDED.baseline_traffic_id,
  proof_traffic_id=EXCLUDED.proof_traffic_id,
  method=EXCLUDED.method, url=EXCLUDED.url, assertion=EXCLUDED.assertion,
  expected_status=EXCLUDED.expected_status, token=EXCLUDED.token,
  created_at=now(), last_checked_at=NULL, last_verdict='', last_note=''`,
		findingID, in.TaskID, in.VulnClass, baselineID, proof.Ref.TrafficID,
		method, strings.TrimSpace(proof.Snapshot.URL), assertion, proof.Snapshot.Status, token)
	return err
}

const findingRegressionCols = `id, finding_id, COALESCE(task_id,0), vulnclass,
baseline_traffic_id, proof_traffic_id, method, url, assertion, expected_status, token,
created_at, last_checked_at, last_verdict, last_note`

func scanFindingRegression(row interface{ Scan(...any) error }) (*FindingRegression, error) {
	var r FindingRegression
	var checked sql.NullTime
	if err := row.Scan(&r.ID, &r.FindingID, &r.TaskID, &r.VulnClass,
		&r.BaselineTrafficID, &r.ProofTrafficID, &r.Method, &r.URL, &r.Assertion,
		&r.ExpectedStatus, &r.Token, &r.CreatedAt, &checked, &r.LastVerdict, &r.LastNote); err != nil {
		return nil, err
	}
	if checked.Valid {
		t := checked.Time
		r.LastCheckedAt = &t
	}
	return &r, nil
}

// GetFindingRegression returns nil, nil when the finding has no spec.
func (d *DB) GetFindingRegression(findingID int64) (*FindingRegression, error) {
	r, err := scanFindingRegression(d.QueryRow(`SELECT `+findingRegressionCols+` FROM finding_regressions WHERE finding_id=$1`, findingID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// ListFindingRegressions is used by the task-level UI/report.
func (d *DB) ListFindingRegressions(taskID int64, limit int) ([]*FindingRegression, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.Query(`SELECT `+findingRegressionCols+` FROM finding_regressions
WHERE task_id=$1 ORDER BY id DESC LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*FindingRegression{}
	for rows.Next() {
		r, err := scanFindingRegression(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordFindingRegressionResult stores the latest deterministic replay verdict.
func (d *DB) RecordFindingRegressionResult(findingID int64, verdict, note string) error {
	_, err := d.Exec(`UPDATE finding_regressions SET last_checked_at=now(), last_verdict=$2, last_note=$3
WHERE finding_id=$1`, findingID, verdict, note)
	return err
}

// MarkFindingRegressionNotReplayable records why a spec cannot currently replay
// (e.g. traffic was pruned). It never fabricates a verdict.
func MarkFindingRegressionNotReplayable(ctx context.Context, tx *sql.Tx, findingID int64, note string) error {
	if tx == nil {
		return nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE finding_regressions SET last_checked_at=now(),
last_verdict='not_replayable', last_note=$2 WHERE finding_id=$1`, findingID, note)
	return err
}
