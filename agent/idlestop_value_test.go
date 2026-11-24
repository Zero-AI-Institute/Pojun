package agent

import (
	"strings"
	"testing"
	"time"
)

func TestValueScoreExtendsIdleThreshold(t *testing.T) {
	fw := &fakeWrites{}
	s := newIdleStopper(fw.get)
	ageStopper(s, time.Hour)
	// 深度验证行为：audit_finding 让价值分落在 [2,5) → 阈值延到 5 轮。
	s.observeTool("audit_finding", []byte(`{"finding_id":1}`), false)

	// 4 轮无写回仍不应收场（阈值被价值分延到 5）。
	for i := 0; i < 4; i++ {
		s.advance()
		if prevent, _ := s.peek(); prevent {
			t.Fatalf("高价值方向第 %d 轮就被收场（应延到 %d 轮）", i+1, idleStopHighRounds)
		}
	}
	s.advance()
	if prevent, reason := s.peek(); !prevent {
		t.Fatalf("到延长阈值 %d 轮应收场", idleStopHighRounds)
	} else if !strings.Contains(reason, "价值分") {
		t.Errorf("收场原因应带价值分: %q", reason)
	}
}

func TestValueScoreHighExtendsToMax(t *testing.T) {
	s := newIdleStopper(nil)
	ageStopper(s, time.Hour)
	for i := 0; i < 5; i++ {
		s.observeTool("report_finding", []byte(`{"severity":"critical","verification_strategy":"poc_replay"}`), false)
	}
	for i := 0; i < idleStopMaxRounds; i++ {
		s.advance()
	}
	// 到 7 轮才收场；前面 6 轮不该提前。
	s.mu.Lock()
	th := s.thresholdLocked()
	s.mu.Unlock()
	if th != idleStopMaxRounds {
		t.Fatalf("高价值阈值 = %d, want %d", th, idleStopMaxRounds)
	}
	if prevent, _ := s.peek(); !prevent {
		t.Fatalf("到 %d 轮应收场", idleStopMaxRounds)
	}
}

func TestValueScoreFailuresShortenThreshold(t *testing.T) {
	s := newIdleStopper(nil)
	ageStopper(s, time.Hour)
	for i := 0; i < 4; i++ {
		s.observeTool("http_request", []byte(`{"url":"https://x"}`), true)
	}
	s.advance()
	if prevent, _ := s.peek(); prevent {
		t.Fatal("第 1 轮不该收场")
	}
	s.advance()
	if prevent, reason := s.peek(); !prevent {
		t.Fatalf("连续工具失败应把阈值缩到 2 轮: %q", reason)
	}
}

func TestValueScoreAssetHits(t *testing.T) {
	if n := highValueAssetHits([]byte(`{"assets":[{"url":"https://x/admin/api"}]}`)); n == 0 {
		t.Fatal("admin/api 资产应算高价值命中")
	}
	if n := highValueAssetHits([]byte(`{"assets":[{"url":"https://x/static/logo.png"}]}`)); n != 0 {
		t.Fatal("静态资源不应算高价值命中")
	}
	// 普通 Bash 探测里的敏感入口给正向信号。
	if !inputHighValue(`curl https://x/api/user/export`) {
		t.Fatal("export/api 入口应被识别")
	}
}

func TestValueTrackerDecays(t *testing.T) {
	v := valueTracker{}
	v.observe("report_finding", []byte(`{"severity":"high"}`), false)
	first := v.score
	v.decay()
	if v.score >= first {
		t.Fatalf("价值分应衰减: %.2f -> %.2f", first, v.score)
	}
}

// 反复扫同一批 admin 路径不能靠关键词把价值分刷高——那正是最该被收掉的空转。
func TestRepeatedScanDoesNotExtendForever(t *testing.T) {
	s := newIdleStopper(nil)
	ageStopper(s, time.Hour)
	for i := 0; i < 3; i++ {
		s.observeTool("Bash", []byte(`curl https://x/admin/api/list`), false)
		s.advance()
	}
	// 3 轮后价值分仍低于延长阈值，应在基准阈值收场，而不是被关键词续命。
	if prevent, reason := s.peek(); !prevent {
		t.Fatalf("重复扫描不应延长空转阈值: %q", reason)
	}
}

func TestPreventRoundsMoveWithExtension(t *testing.T) {
	s := newIdleStopper(nil)
	s.value.score = idleStopValueHigh
	s.mu.Lock()
	th := s.thresholdLocked()
	pr := s.preventRoundsLocked()
	s.mu.Unlock()
	if th != idleStopMaxRounds {
		t.Fatalf("threshold = %d", th)
	}
	if pr <= th {
		t.Fatalf("preventRounds(%d) 必须晚于 threshold(%d)，否则提示与终止同轮", pr, th)
	}
}
