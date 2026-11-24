package db

import (
	"database/sql"
	"errors"
)

// SetTaskEgressSnapshot writes the task's build-time egress receipt (issue #39).
// raw must already be redacted by the caller: this column is read by API handlers,
// diagnostics bundles and DB dumps, so no proxy credential may ever reach it.
//
// The write is monotonic on captured_at: the snapshot is persisted after the
// agent-build lock is released, so a slow writer can otherwise overwrite a newer
// receipt produced by a rebuild that finished first. All writers emit RFC3339 in
// UTC, which orders lexicographically, so a plain string comparison suffices.
func (d *DB) SetTaskEgressSnapshot(taskID int64, raw []byte) error {
	_, err := d.Exec(
		`UPDATE tasks SET egress_snapshot=$2::jsonb
		  WHERE id=$1 AND deleted_at IS NULL
		    AND (egress_snapshot IS NULL
		         OR COALESCE(egress_snapshot->>'captured_at','') <= ($2::jsonb->>'captured_at'))`,
		taskID, string(raw),
	)
	return err
}

// GetTaskEgressSnapshot returns the raw receipt JSON for a live task.
// found=false means the task row does not exist (or is deleted/archived);
// a NULL column returns (nil, true, nil) — the task exists but was never built.
func (d *DB) GetTaskEgressSnapshot(taskID int64) (raw []byte, found bool, err error) {
	var s sql.NullString
	err = d.QueryRow(
		`SELECT egress_snapshot::text FROM tasks WHERE id=$1 AND deleted_at IS NULL`,
		taskID,
	).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !s.Valid || s.String == "" {
		return nil, true, nil
	}
	return []byte(s.String), true, nil
}
