package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// read_output（v0.4.92）：行窗口回读 + 路径夹逼（basename，防越界）。
func TestReadOutputWindowAndScope(t *testing.T) {
	dir := t.TempDir()
	ts := &ToolSet{runDir: dir}
	outDir := cmdOutDir(dir)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := 1; i <= 250; i++ {
		b.WriteString("line-")
		b.WriteString(strings.Repeat("x", 0))
		b.WriteString(itoa2(i))
		b.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(outDir, "output-1.txt"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	// 越界文件（在 runDir 根而非 cmd-output）
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("top secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	call := func(args string) string {
		res, err := ts.readOutput().Call(context.Background(), json.RawMessage(args), nil)
		if err != nil {
			t.Fatalf("Call err: %v", err)
		}
		return res.Flatten()
	}

	// 1) 默认窗口（1–100）
	out := call(`{"file":"output-1.txt"}`)
	if !strings.Contains(out, "共 250 行") || !strings.Contains(out, "第 1–100 行") {
		t.Fatalf("默认窗口不符: %s", clipStrTest(out, 200))
	}
	// 2) 翻页
	out = call(`{"file":"output-1.txt","offset":200,"lines":60}`)
	if !strings.Contains(out, "第 200–250 行") || !strings.Contains(out, "line-250") {
		t.Fatalf("翻页不符: %s", clipStrTest(out, 300))
	}
	// 3) 越界 offset 提示
	out = call(`{"file":"output-1.txt","offset":9999}`)
	if !strings.Contains(out, "超出总行数") {
		t.Fatalf("越界 offset 应提示: %s", out)
	}
	// 4) 路径夹逼：传 runDir 根的 secret.txt（basename 落 cmd-output 下不存在）
	out = call(`{"file":"secret.txt"}`)
	if !strings.Contains(out, "文件不存在") {
		t.Fatalf("夹逼失败（读到了目录外文件）: %s", out)
	}
	// 5) 完整路径也给 basename 化处理（JSON Marshal 处理 Windows 反斜杠）
	fullPathArgs, _ := json.Marshal(map[string]string{"file": filepath.Join(dir, "cmd-output", "output-1.txt")})
	out = call(string(fullPathArgs))
	if !strings.Contains(out, "共 250 行") {
		t.Fatalf("完整路径应 basename 化后可读: %s", clipStrTest(out, 150))
	}
	// 6) 无 runDir
	ts2 := &ToolSet{}
	if res, _ := ts2.readOutput().Call(context.Background(), json.RawMessage(`{"file":"a.txt"}`), nil); !strings.Contains(res.Flatten(), "没有工作目录") {
		t.Fatal("无 runDir 应报错")
	}
}

// clipStr 截断字符串防止 Fatalf 里 slice panic。
func clipStrTest(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// itoa2 是测试内的整型转字符串（避免与 agent 包内工具重名）。
func itoa2(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
