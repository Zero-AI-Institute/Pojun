package server

import (
	"testing"

	"github.com/chu0119/pojun/db"
)

func TestSettleTerminalStatusBudget(t *testing.T) {
	// budget stop with no goals must not look like a successful done.
	if got := settleTerminalStatus(0, 0, "budget", false); got != "timeout" {
		t.Fatalf("budget no-goal = %q, want timeout", got)
	}
	// all goals met before the budget stop → done is honest.
	if got := settleTerminalStatus(2, 2, "budget", false); got != "done" {
		t.Fatalf("budget all-met = %q, want done", got)
	}
}

func TestTaskBudgetConfigEnabled(t *testing.T) {
	if (taskBudgetConfig{}).enabled() {
		t.Fatal("zero config must be disabled")
	}
	if !(taskBudgetConfig{Tokens: 1}).enabled() {
		t.Fatal("token config must be enabled")
	}
}

func TestTaskBudgetFromPGSettings(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil || dsn == "" {
		t.Skip("requires POJUN_PG_DSN")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()
	keys := []string{settingTaskBudgetTokens, settingTaskBudgetUSD, settingTaskBudgetMinutes, settingTaskBudgetWarnPct}
	for _, k := range keys {
		_, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, k)
	}
	defer func() {
		for _, k := range keys {
			_, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, k)
		}
	}()
	_ = d.SetSetting(settingTaskBudgetTokens, "500000")
	_ = d.SetSetting(settingTaskBudgetUSD, "1.25")
	_ = d.SetSetting(settingTaskBudgetMinutes, "60")
	_ = d.SetSetting(settingTaskBudgetWarnPct, "75")
	cfg := taskBudgetFromPG(d)
	if cfg.Tokens != 500000 || cfg.USD != 1.25 || cfg.Minutes != 60 || cfg.WarnPct != 75 {
		t.Fatalf("cfg=%+v", cfg)
	}
}
