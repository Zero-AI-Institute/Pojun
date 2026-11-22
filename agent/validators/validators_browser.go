package validators

import (
	"context"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// chromeCandidates 是无头浏览器的常见可执行名（Kali chromium / Debian
// chromium-browser / 官方 chrome）。hostd 工具清单会装 chromium；找不到则
// 浏览器断言跳过（反射证据维持 warn）。
var chromeCandidates = []string{
	"chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
	"/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome-stable",
}

// ChromeAvailable 报告本机是否有可用的无头浏览器。
func ChromeAvailable() bool {
	for _, c := range chromeCandidates {
		if _, err := exec.LookPath(c); err == nil {
			return true
		}
	}
	return false
}

// BrowserExecResult 是浏览器执行断言的结果。
type BrowserExecResult struct {
	Executed bool   `json:"executed"` // alert() 弹窗真实触发 = payload 执行级证据
	Skipped  bool   `json:"skipped"`  // 本机无浏览器（或启动失败）= 断言跳过
	Detail   string `json:"detail"`
}

// ProbeBrowserExec 用无头浏览器加载探针页面并断言 alert() 弹窗真实触发——
// XSS 执行级证据（反射确认之上再进一步，对标 XBOW validators 的 headless 断言）。
// proxyURL 非空时浏览器探针走该代理（与平台出口一致，不留真实 IP——OPSEC 纪律）。
// 总预算 15s；弹窗触发即应答（HandleJavaScriptDialog）避免阻塞页面。
func ProbeBrowserExec(ctx context.Context, probeURL, proxyURL string) BrowserExecResult {
	if !ChromeAvailable() {
		return BrowserExecResult{Skipped: true, Detail: "本机无 chromium/chrome，执行断言跳过（反射证据维持 warn）"}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("no-sandbox", true), // Kali/容器可能 root 运行
		chromedp.Flag("disable-gpu", true),
	)
	if proxyURL != "" {
		opts = append(opts, chromedp.ProxyServer(proxyURL))
	}
	for _, c := range chromeCandidates {
		if path, err := exec.LookPath(c); err == nil {
			opts = append(opts, chromedp.ExecPath(path)) // 明确指定，避免默认探测选错
			break
		}
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()
	taskCtx, cancelTask := chromedp.NewContext(allocCtx)
	defer cancelTask()

	var executed atomic.Bool
	dialogs := chromedp.Events(taskCtx, page.JavascriptDialogOpening)
	go func() {
		for _, err := range dialogs {
			if err != nil {
				return
			}
			executed.Store(true) // alert 弹窗真实触发 = payload 已执行
			// 弹窗必须应答否则页面挂死（示例模式：同一 taskCtx 上 Call）。
			_, _ = chromedp.Call(taskCtx, page.HandleJavaScriptDialog, page.HandleJavaScriptDialogParams{Accept: true})
		}
	}()

	// v0.24：Run 是泛型单 Action，多步用 Steps 组合。
	var evErr error
	_, evErr = chromedp.Run(taskCtx, chromedp.Steps(
		chromedp.Navigate(probeURL),
		chromedp.Sleep(3*time.Second), // 给 onload/onerror 一点触发窗口
	))
	if evErr != nil {
		if executed.Load() {
			return BrowserExecResult{Executed: true, Detail: "页面加载因弹窗中断，但 alert() 弹窗已真实触发"}
		}
		return BrowserExecResult{Skipped: true, Detail: "浏览器加载失败：" + trimErr(evErr) + "（执行断言跳过）"}
	}
	return BrowserExecResult{
		Executed: executed.Load(),
		Detail: verdictText(executed.Load(),
			"无头浏览器加载探针页面，alert() 弹窗真实触发——XSS 执行级证据",
			"页面已加载但未触发弹窗（payload 可能被 DOM 结构/CSP 拦截）",
		),
	}
}

// trimErr 缩短 chromedp 错误文本。
func trimErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
