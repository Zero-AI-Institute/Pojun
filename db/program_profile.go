package db

// SRC/众测 program profile（v0.4.112）。
//
// 这不是授权范围的替代品：真正的可测范围仍由 task_scope 与 task_constraints
// 决定。profile 只承载 program 的平台/handle、公开 scope/excluded、允许的扫描器、
// 目标 RPS、dry-run/allow_race 等元数据，用于提示模型与对原生 HTTP 工具做轻量
// 限速。NULL=未配置，现有任务行为完全不变。
//
// 刻意不把凭据/API Key 放进 profile：凭据走 auth_config / vault，profile 会被
// 诊断包与 API 原样返回。

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	ProgramProfileMaxScope      = 200
	ProgramProfileMaxExcluded   = 200
	ProgramProfileMaxScanners   = 50
	ProgramProfileMaxItemRunes  = 300
	ProgramProfileMaxRPS        = 100
	ProgramProfileMaxHosts      = 200
	ProgramProfileMaxConcurrent = 32
)

var ErrTaskNotFound = errors.New("task not found")

type ProgramProfile struct {
	Platform        string   `json:"platform,omitempty"` // hackerone/bugcrowd/intigriti/yeswehack/other
	Handle          string   `json:"handle,omitempty"`
	Scope           []string `json:"scope,omitempty"`
	Excluded        []string `json:"excluded,omitempty"`
	ScannersAllowed []string `json:"scanners_allowed,omitempty"`
	AllowRace       bool     `json:"allow_race,omitempty"`
	DryRun          bool     `json:"dry_run,omitempty"`
	RPS             float64  `json:"rps,omitempty"` // 0 = 不限速
	// P2-4 第一批：只对原生 HTTP 执行器生效的硬边界。空 allowlist = 不限制；
	// denied 永远优先。host 支持精确匹配或 *.example.com 通配。
	AllowedHosts  []string `json:"allowed_hosts,omitempty"`
	DeniedHosts   []string `json:"denied_hosts,omitempty"`
	WindowStart   string   `json:"window_start,omitempty"` // HH:MM（本地/指定时区）
	WindowEnd     string   `json:"window_end,omitempty"`
	Timezone      string   `json:"timezone,omitempty"` // IANA，空=服务器本地
	MaxConcurrent int      `json:"max_concurrent,omitempty"`
}

// Normalize trims/dedupes and rejects values that would bloat prompts or make
// rate limiting ambiguous. It mutates the receiver.
func (p *ProgramProfile) Normalize() error {
	if p == nil {
		return nil
	}
	p.Platform = strings.ToLower(strings.TrimSpace(p.Platform))
	p.Handle = strings.TrimSpace(p.Handle)
	if len([]rune(p.Platform)) > 32 {
		return fmt.Errorf("platform 超过 32 字")
	}
	if len([]rune(p.Handle)) > 128 {
		return fmt.Errorf("handle 超过 128 字")
	}
	if hasProfileControl(p.Platform) || hasProfileControl(p.Handle) {
		return fmt.Errorf("platform/handle 含控制字符")
	}
	var err error
	if p.Scope, err = normalizeProfileList(p.Scope, ProgramProfileMaxScope, ProgramProfileMaxItemRunes); err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	if p.Excluded, err = normalizeProfileList(p.Excluded, ProgramProfileMaxExcluded, ProgramProfileMaxItemRunes); err != nil {
		return fmt.Errorf("excluded: %w", err)
	}
	if p.ScannersAllowed, err = normalizeProfileList(p.ScannersAllowed, ProgramProfileMaxScanners, 64); err != nil {
		return fmt.Errorf("scanners_allowed: %w", err)
	}
	if p.AllowedHosts, err = normalizeHostList(p.AllowedHosts, ProgramProfileMaxHosts); err != nil {
		return fmt.Errorf("allowed_hosts: %w", err)
	}
	if p.DeniedHosts, err = normalizeHostList(p.DeniedHosts, ProgramProfileMaxHosts); err != nil {
		return fmt.Errorf("denied_hosts: %w", err)
	}
	p.WindowStart = strings.TrimSpace(p.WindowStart)
	p.WindowEnd = strings.TrimSpace(p.WindowEnd)
	if (p.WindowStart == "") != (p.WindowEnd == "") {
		return fmt.Errorf("window_start/window_end 必须同时配置")
	}
	if p.WindowStart != "" {
		if _, err := time.Parse("15:04", p.WindowStart); err != nil {
			return fmt.Errorf("window_start 必须是 HH:MM")
		}
		if _, err := time.Parse("15:04", p.WindowEnd); err != nil {
			return fmt.Errorf("window_end 必须是 HH:MM")
		}
	}
	p.Timezone = strings.TrimSpace(p.Timezone)
	if p.Timezone != "" {
		if _, err := time.LoadLocation(p.Timezone); err != nil {
			return fmt.Errorf("timezone 非法: %v", err)
		}
	}
	if p.MaxConcurrent < 0 || p.MaxConcurrent > ProgramProfileMaxConcurrent {
		return fmt.Errorf("max_concurrent 必须在 0-%d 之间", ProgramProfileMaxConcurrent)
	}
	if math.IsNaN(p.RPS) || math.IsInf(p.RPS, 0) || p.RPS < 0 || p.RPS > ProgramProfileMaxRPS {
		return fmt.Errorf("rps 必须在 0-%d 之间", ProgramProfileMaxRPS)
	}
	if p.RPS > 0 {
		p.RPS = float64(int(p.RPS*100+0.5)) / 100
		if p.RPS < 0.01 {
			p.RPS = 0.01
		}
	}
	return nil
}

func (p *ProgramProfile) IsZero() bool {
	return p == nil || (p.Platform == "" && p.Handle == "" && len(p.Scope) == 0 &&
		len(p.Excluded) == 0 && len(p.ScannersAllowed) == 0 &&
		len(p.AllowedHosts) == 0 && len(p.DeniedHosts) == 0 &&
		p.WindowStart == "" && p.WindowEnd == "" && p.Timezone == "" &&
		!p.AllowRace && !p.DryRun && p.RPS == 0 && p.MaxConcurrent == 0)
}

// hasProfileControl rejects CR/LF/TAB/DEL and other C0 controls: profile strings
// are rendered into prompts and handle is injected as an HTTP header value.
func hasProfileControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// normalizeHostList lowercases and trims host patterns, allowing exact hosts
// and leading "*." wildcards. URLs/paths are rejected to avoid ambiguous scope.
func normalizeHostList(in []string, maxItems int) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if hasProfileControl(s) || len([]rune(s)) > 253 {
			return nil, fmt.Errorf("host 含控制字符或超过 253 字")
		}
		if strings.ContainsAny(s, "/?#@ 	") {
			return nil, fmt.Errorf("host 不能包含 URL/路径/空白: %q", s)
		}
		if strings.HasPrefix(s, "*.") {
			if len(s) <= 2 {
				return nil, fmt.Errorf("通配 host 非法: %q", s)
			}
		} else if strings.Contains(s, "*") {
			return nil, fmt.Errorf("只支持 *.example.com 形式通配: %q", s)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) > maxItems {
			return nil, fmt.Errorf("超过 %d 条", maxItems)
		}
	}
	return out, nil
}

func normalizeProfileList(in []string, maxItems, maxRunes int) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if len([]rune(s)) > maxRunes {
			return nil, fmt.Errorf("单条超过 %d 字", maxRunes)
		}
		if hasProfileControl(s) {
			return nil, fmt.Errorf("含控制字符")
		}
		k := strings.ToLower(s)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
		if len(out) > maxItems {
			return nil, fmt.Errorf("超过 %d 条", maxItems)
		}
	}
	return out, nil
}

// GetTaskProgramProfile returns the profile and whether the task exists. A NULL
// column yields (nil, true, nil): the task exists but has no profile.
func (d *DB) GetTaskProgramProfile(taskID string) (*ProgramProfile, bool, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(taskID), 10, 64)
	if err != nil || id <= 0 {
		return nil, false, nil
	}
	var raw []byte
	err = d.QueryRow(`SELECT program_profile FROM tasks WHERE id=$1 AND deleted_at IS NULL`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(raw) == 0 {
		return nil, true, nil
	}
	var p ProgramProfile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, true, fmt.Errorf("program profile JSON 损坏: %w", err)
	}
	if err := p.Normalize(); err != nil {
		return nil, true, fmt.Errorf("program profile 非法: %w", err)
	}
	if p.IsZero() {
		return nil, true, nil
	}
	return &p, true, nil
}

// SaveTaskProgramProfile validates and stores the profile. An empty profile
// clears the column (NULL), so "reset" is explicit and idempotent.
func (d *DB) SaveTaskProgramProfile(taskID string, p *ProgramProfile) error {
	id, err := strconv.ParseInt(strings.TrimSpace(taskID), 10, 64)
	if err != nil || id <= 0 {
		return ErrTaskNotFound
	}
	if p != nil {
		if err := p.Normalize(); err != nil {
			return err
		}
	}
	var raw any
	if p != nil && !p.IsZero() {
		b, err := json.Marshal(p)
		if err != nil {
			return err
		}
		raw = string(b)
	}
	res, err := d.Exec(`UPDATE tasks SET program_profile=$2::jsonb
WHERE id=$1 AND deleted_at IS NULL`, id, raw)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTaskNotFound
	}
	return nil
}
