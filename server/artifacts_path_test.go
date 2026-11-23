package server

import (
	"os"
	"path/filepath"
	"testing"
)

// v0.4.99：证据路径允许用 .. 回到任务根（小程序产物在 tasks/<id>/miniapp/），
// 但不得越出任务目录。
func TestResolveArtifactPath(t *testing.T) {
	root := t.TempDir()
	taskRoot := filepath.Join(root, "tasks", "1")
	runDir := filepath.Join(taskRoot, "i2")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srcDir := filepath.Join(taskRoot, "miniapp", "wx1234567890abcdef", "source")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(srcDir, "app-service.js")
	if err := os.WriteFile(target, []byte("var a=1"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got, err := resolveArtifactPath(taskRoot, runDir, "../miniapp/wx1234567890abcdef/source/app-service.js"); err != nil || got != target {
		t.Fatalf("任务根内 .. 应允许: got=%q err=%v", got, err)
	}
	if _, err := resolveArtifactPath(taskRoot, runDir, "../../etc/passwd"); err == nil {
		t.Fatal("越出任务根的 .. 应拒绝")
	}
	if _, err := resolveArtifactPath(taskRoot, runDir, target); err == nil {
		t.Fatal("绝对路径应拒绝")
	}
	if _, err := resolveArtifactPath(taskRoot, "", "a.js"); err == nil {
		t.Fatal("空 runDir 应拒绝")
	}
	if _, err := resolveArtifactPath(taskRoot, runDir, "   "); err == nil {
		t.Fatal("空 path 应拒绝")
	}
	// 名字以 .. 开头但不是父目录（如 ..foo）应允许。
	if err := os.WriteFile(filepath.Join(runDir, "..foo"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveArtifactPath(taskRoot, runDir, "..foo"); err != nil {
		t.Fatalf("..foo 不应被误判为越界: %v", err)
	}
}
