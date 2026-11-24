package db

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// 回归守卫：egress_snapshot 绝不进 taskCols——ListTasks/GetTask 会扫描全部活任务，
// 把回执 JSONB 塞进热路径会让每个任务都多一次解析。
func TestTaskEgressSnapshotNotInTaskCols(t *testing.T) {
	if strings.Contains(taskCols, "egress_snapshot") {
		t.Fatal("taskCols 不得包含 egress_snapshot（任务列表热路径）")
	}
}

// t.Cleanup 是后进先出：关连接必须最先注册，数据清理随后注册，
// 才能保证「先清数据、后关连接」。用 defer d.Close() 会让 defer 先于
// 所有 t.Cleanup 执行，清理语句落在已关闭的连接上并被静默丢弃，
// 每次运行都向共享库泄漏 task/archive 行（见 db/company_scope_test.go 同款教训）。
func TestTaskEgressSnapshotRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateTaskWithOptions("egress snapshot test", "round trip", TaskCreateOptions{})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	t.Cleanup(func() {
		if err := d.DeleteTask(task.ID); err != nil {
			t.Errorf("cleanup delete task %d: %v", task.ID, err)
		}
	})

	// Never built → task exists, column NULL.
	raw, found, err := d.GetTaskEgressSnapshot(task.ID)
	if err != nil || !found || len(raw) != 0 {
		t.Fatalf("initial get = (%q, %v, %v), want (empty, true, nil)", raw, found, err)
	}

	snap := []byte(`{"schema_version":1,"captured_at":"2026-11-23T12:00:00Z","egress":{"kind":"direct","address":"","has_auth":false,"parse_ok":true},"ua":{"surfaces":[]}}`)
	if err := d.SetTaskEgressSnapshot(task.ID, snap); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}
	got, found, err := d.GetTaskEgressSnapshot(task.ID)
	if err != nil || !found {
		t.Fatalf("get after set = (%v, %v)", found, err)
	}
	var want, have any
	if err := json.Unmarshal(snap, &want); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	if err := json.Unmarshal(got, &have); err != nil {
		t.Fatalf("unmarshal got: %v", err)
	}
	if !reflect.DeepEqual(want, have) {
		t.Fatalf("round trip mismatch:\nwant %s\ngot  %s", snap, got)
	}

	// 落库在装配锁外执行，慢写可能晚于一次更快的重建；captured_at 更旧的写入
	// 必须被丢弃，否则任务页会回退到过期出口。
	stale := []byte(`{"schema_version":1,"captured_at":"2026-11-23T11:00:00Z","egress":{"kind":"proxy_pool","address":"http://stale:1","has_auth":false,"parse_ok":true},"ua":{"surfaces":[]}}`)
	if err := d.SetTaskEgressSnapshot(task.ID, stale); err != nil {
		t.Fatalf("set stale snapshot: %v", err)
	}
	got, _, err = d.GetTaskEgressSnapshot(task.ID)
	if err != nil {
		t.Fatalf("get after stale write: %v", err)
	}
	var staleCheck struct {
		Egress struct{ Kind string } `json:"egress"`
	}
	if err := json.Unmarshal(got, &staleCheck); err != nil || staleCheck.Egress.Kind != "direct" {
		t.Fatalf("旧快照覆盖了较新的回执: kind=%q err=%v", staleCheck.Egress.Kind, err)
	}

	// Soft-deleted (archived) tasks must be invisible.
	if _, err := d.Exec(`UPDATE tasks SET deleted_at=now() WHERE id=$1`, task.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, found, err := d.GetTaskEgressSnapshot(task.ID); err != nil || found {
		t.Fatalf("deleted task get = (found=%v, err=%v), want (false, nil)", found, err)
	}
}

// 归档必须显式清空出口回执：归档 stub 会一直留在 tasks 行里，若不清空，
// 恢复后任务页会展示归档前的陈旧「已构建」回执；restoreTaskStub 的显式
// 列清单不含该列，因此恢复后保持 NULL，直到下一次 Agent 装配重新写入。
func TestTaskArchiveClearsEgressSnapshot(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}

	task, err := d.CreateTaskWithOptions("archive clears egress", "goal", TaskCreateOptions{})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	t.Cleanup(func() {
		if _, err := d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID); err != nil {
			t.Errorf("cleanup task_archives for %d: %v", task.ID, err)
		}
		if err := d.DeleteTask(task.ID); err != nil {
			t.Errorf("cleanup delete task %d: %v", task.ID, err)
		}
	})
	raw := []byte(`{"schema_version":1,"captured_at":"2026-11-23T12:00:00Z","egress":{"kind":"direct","has_auth":false,"parse_ok":true},"ua":{"surfaces":[]}}`)
	if err := d.SetTaskEgressSnapshot(task.ID, raw); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}
	// 归档前置条件：任务已暂停或处于终态（与任务页归档按钮同一约束）。
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatalf("pause task: %v", err)
	}

	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatalf("queue archive: %v", err)
	}
	// ClaimTaskArchiveJob 是全局队列（ORDER BY requested_at,id LIMIT 1）：共享库上
	// 若有更早的遗留队列行，这里会领到别人的任务。断言拿到的就是本用例排队的那条，
	// 否则后续 CompleteTaskArchive 只会报含糊的 identity/state mismatch。
	claimed, err := d.ClaimTaskArchiveJob(t.Context())
	if err != nil {
		t.Fatalf("claim archive: %v", err)
	}
	if claimed == nil || claimed.ID != archive.ID {
		t.Fatalf("claim archive 领到 %+v，want id=%d（库里有更早的遗留队列行，先清理）", claimed, archive.ID)
	}
	snap, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatalf("snapshot archive: %v", err)
	}
	if err := d.CompleteTaskArchive(archive.ID, snap, "/tmp/test-egress.tar", "abc", 1, 1); err != nil {
		t.Fatalf("complete archive: %v", err)
	}
	var isNull bool
	if err := d.QueryRow(`SELECT egress_snapshot IS NULL FROM tasks WHERE id=$1`, task.ID).Scan(&isNull); err != nil {
		t.Fatalf("read archived stub: %v", err)
	}
	if !isNull {
		t.Fatal("归档后 egress_snapshot 必须为 NULL")
	}

	if _, err := d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatalf("queue restore: %v", err)
	}
	claimedRestore, err := d.ClaimTaskArchiveJob(t.Context())
	if err != nil {
		t.Fatalf("claim restore: %v", err)
	}
	if claimedRestore == nil || claimedRestore.ID != archive.ID {
		t.Fatalf("claim restore 领到 %+v，want id=%d", claimedRestore, archive.ID)
	}
	if _, err := d.RestoreTaskArchive(archive.ID, snap, 600); err != nil {
		t.Fatalf("restore archive: %v", err)
	}
	if err := d.QueryRow(`SELECT egress_snapshot IS NULL FROM tasks WHERE id=$1`, task.ID).Scan(&isNull); err != nil {
		t.Fatalf("read restored stub: %v", err)
	}
	if !isNull {
		t.Fatal("恢复后不得回填归档前的 egress_snapshot")
	}
}
