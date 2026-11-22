package validators

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 测试目标工厂：按 query 参数构造可预测的响应。
// echoVal != "" → 原样回显该参数值（RCE 回显/XSS 反射共用）；
// sleepMS > 0 且参数含 sleep 探针 → 按时延模拟盲注；
// filePayload → 参数为 file:///etc/passwd 时回 root:x:0:0。
func testTarget(t *testing.T, echoVal string, sleepMS int, filePayload bool) (*httptest.Server, map[string]string) {
	t.Helper()
	seen := map[string]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("q")
		seen[val] = r.URL.RawQuery
		if strings.Contains(val, "sleep") && sleepMS > 0 {
			time.Sleep(time.Duration(sleepMS) * time.Millisecond)
		}
		if filePayload && strings.Contains(val, "file:///etc/passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		if echoVal != "" {
			_, _ = w.Write([]byte("result: " + val))
			return
		}
		_, _ = w.Write([]byte("nothing interesting"))
	})
	return httptest.NewServer(mux), seen
}

// RCE 回显型：目标把参数值直接拼进命令回显 → echo token 命中 → pass + 标记。
func TestRunRCEEchoPass(t *testing.T) {
	ts, _ := testTarget(t, "", 0, false)
	defer ts.Close()
	// 回显型目标：把参数值原样返回（等价于响应包含 echo 输出的 token）
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		// 模拟拼接执行：探针里的 echo 不存在，但目标「回显输入」的缺陷会把 token 带出来
		if strings.Contains(v, "echo ") {
			i := strings.Index(v, "echo ")
			_, _ = w.Write([]byte("cmd out: " + v[i+5:]))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	res := RunRCE(context.Background(), ts.Client(), server.URL+"?q=1", "q", NewToken())
	if res.Verdict != VerdictPass {
		t.Fatalf("回显型 RCE 应 pass，得 %s：%+v", res.Verdict, res.Probes)
	}
	if res.Marker == "" || !strings.HasPrefix(res.Marker, "validate:") || !strings.HasSuffix(res.Marker, ":pass") {
		t.Fatalf("pass 应带机验标记: %q", res.Marker)
	}
}

// RCE 时延型：无回显、按 sleep 时延判定（阈值用包内可覆盖变量，测试用短值）。
func TestRunRCETimingPass(t *testing.T) {
	oldSleep, oldThreshold := rceSleepSeconds, rceTimingThreshold
	rceSleepSeconds, rceTimingThreshold = 1, 500*time.Millisecond
	t.Cleanup(func() { rceSleepSeconds, rceTimingThreshold = oldSleep, oldThreshold })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		if strings.Contains(v, "sleep") {
			time.Sleep(time.Duration(rceSleepSeconds) * time.Second)
		}
		_, _ = w.Write([]byte("no echo"))
	}))
	defer server.Close()

	res := RunRCE(context.Background(), server.Client(), server.URL+"?q=1", "q", NewToken())
	if res.Verdict != VerdictPass || res.Note == "" || !strings.Contains(res.Note, "盲注") {
		t.Fatalf("时延型应 pass+盲注 note: %s %s", res.Verdict, res.Note)
	}
}

// RCE 全未命中 → fail。
func TestRunRCEFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("clean"))
	}))
	defer server.Close()
	res := RunRCE(context.Background(), server.Client(), server.URL+"?q=1", "q", NewToken())
	if res.Verdict != VerdictFail || res.Marker != "" {
		t.Fatalf("未命中应 fail 无标记: %s", res.Verdict)
	}
}

// XSS：未转义原样反射+无 CSP → pass；反射+严格 CSP → warn；转义反射 → fail。
func TestRunXSSRawReflectionPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("echo: " + r.URL.Query().Get("q")))
	}))
	defer server.Close()
	res := RunXSS(context.Background(), server.Client(), server.URL+"?q=1", "q", NewToken())
	if res.Verdict != VerdictPass || res.Marker == "" {
		t.Fatalf("原样反射应 pass: %s %+v", res.Verdict, res.Probes)
	}
}

func TestRunXSSStrictCSPWarn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		_, _ = w.Write([]byte("echo: " + r.URL.Query().Get("q")))
	}))
	defer server.Close()
	res := RunXSS(context.Background(), server.Client(), server.URL+"?q=1", "q", NewToken())
	if res.Verdict != VerdictWarn || res.Marker != "" || !strings.Contains(res.Note, "CSP") {
		t.Fatalf("严格 CSP 应 warn 无标记: %s note=%s", res.Verdict, res.Note)
	}
}

func TestRunXSSEscapedFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		v = strings.ReplaceAll(v, "<", "&lt;")
		_, _ = w.Write([]byte("echo: " + v))
	}))
	defer server.Close()
	res := RunXSS(context.Background(), server.Client(), server.URL+"?q=1", "q", NewToken())
	if res.Verdict != VerdictFail || !strings.Contains(res.Note, "转义") {
		t.Fatalf("转义反射应 fail: %s note=%s", res.Verdict, res.Note)
	}
}

// SSRF：响应特征型 → pass；OOB 假通道 → pass；Note 透传。
func TestRunSSRFFileResponsePass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		if strings.Contains(v, "file:///etc/passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	res := RunSSRF(context.Background(), server.Client(), server.URL+"?q=1", "q", NewToken(), SSRFOOB{})
	if res.Verdict != VerdictPass || !strings.Contains(res.Note, "回读") {
		t.Fatalf("文件读取型应 pass: %s note=%s", res.Verdict, res.Note)
	}
}

func TestRunSSRFOOBPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	hitToken := ""
	res := RunSSRF(context.Background(), server.Client(), server.URL+"?q=1", "q", NewToken(), SSRFOOB{
		Base: "http://10.0.0.9:9999",
		WaitOOB: func(tok string, timeout time.Duration) bool {
			hitToken = tok
			return true
		},
	})
	if res.Verdict != VerdictPass || hitToken == "" || !strings.Contains(res.Note, "OOB") {
		t.Fatalf("OOB 应 pass: %s note=%s token=%q", res.Verdict, res.Note, hitToken)
	}
}

func TestRunSSRFNotePassthrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("clean"))
	}))
	defer server.Close()
	res := RunSSRF(context.Background(), server.Client(), server.URL+"?q=1", "q", NewToken(), SSRFOOB{
		Note: "监听不可用",
	})
	if res.Verdict != VerdictFail || !strings.Contains(res.Note, "监听不可用") {
		t.Fatalf("Note 应透传: %s note=%s", res.Verdict, res.Note)
	}
}

// inject：参数替换/追加与非法 scheme 拒绝。
func TestInjectParam(t *testing.T) {
	u, err := inject("http://t/ping?host=x&z=2", "host", ";echo T")
	if err != nil || !strings.Contains(u, "host=%3Becho+T") || !strings.Contains(u, "z=2") {
		t.Fatalf("参数替换异常: %v %s", err, u)
	}
	u2, err := inject("http://t/ping", "q", "v")
	if err != nil || !strings.Contains(u2, "q=v") {
		t.Fatalf("参数追加异常: %v %s", err, u2)
	}
	if _, err := inject("ftp://t/a", "q", "v"); err == nil {
		t.Fatal("非 http/https 应拒绝")
	}
}
