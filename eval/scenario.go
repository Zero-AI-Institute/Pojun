// Package eval 是破军的离线评测 harness（P1-4）。
//
// 它不负责启动靶场，只负责把一次真实任务运行折算成可比较的指标：
// 目标达成、预期漏洞命中、证据完整度、阶段覆盖、额外发现、token/成本/耗时。
// 场景 manifest 固定了“这道题应该拿到什么”，因此同一任务在两次运行/两个模型/
// 两个版本之间的差异可以用 JSON diff 直接对比，而不是靠人读报告。
//
// 设计约束：
//   - 只读：评分不修改任务、不重跑 agent、不发网络请求；
//   - 可复现：所有指标来自 DB 持久化数据，同一份数据多次评分结果一致；
//   - 先命中后判分：预期项按 vulnclass(+asset/severity) 匹配，证据长度独立计分；
//   - 额外发现不直接叫误报：没有人工复核时只能叫 unexpected，报告里明确标注。
package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Scenario 是一道评测题的定义。target/setup 只是给人/运行器看的元数据；
// ScoreTask 只用 expected/stages/require_goal/预算字段做评分。
type Scenario struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Source      string            `json:"source,omitempty"` // dvwa/juice-shop/vulhub/ad/custom
	Setup       string            `json:"setup,omitempty"`  // 靶场启动命令/说明
	Target      string            `json:"target,omitempty"` // 目标 URL/主机（元数据）
	Goal        string            `json:"goal"`
	Stages      []string          `json:"stages,omitempty"` // 期望覆盖的维度：recon/authz/injection/...
	Expected    []ExpectedFinding `json:"expected"`
	RequireGoal bool              `json:"require_goal,omitempty"` // 是否要求所有 goal 都 met 才算 pass
	MaxMinutes  int               `json:"max_minutes,omitempty"`
	MaxUSD      float64           `json:"max_usd,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Notes       string            `json:"notes,omitempty"`
}

// ExpectedFinding 是一条 ground truth。Optional=true 表示加分项，不参与 pass 判定。
// MinEvidenceRunes=0 用默认 120；<0 表示不检查证据长度。
type ExpectedFinding struct {
	VulnClass        string `json:"vulnclass"`
	Asset            string `json:"asset,omitempty"`    // 匹配资产 URL/domain/ip 的子串
	Severity         string `json:"severity,omitempty"` // 可选，要求精确匹配
	Optional         bool   `json:"optional,omitempty"`
	MinEvidenceRunes int    `json:"min_evidence_runes,omitempty"`
}

const defaultMinEvidenceRunes = 120

func (e ExpectedFinding) minEvidence() int {
	if e.MinEvidenceRunes < 0 {
		return 0
	}
	if e.MinEvidenceRunes == 0 {
		return defaultMinEvidenceRunes
	}
	return e.MinEvidenceRunes
}

// LoadScenario 读取并校验一个 manifest。
func LoadScenario(path string) (*Scenario, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Scenario
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// LoadScenarios 读取目录下所有 *.json（按文件名排序），并检查 ID 唯一。
func LoadScenarios(dir string) ([]*Scenario, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		paths = append(paths, filepath.Join(dir, e.Name()))
	}
	sort.Strings(paths)
	out := make([]*Scenario, 0, len(paths))
	seen := map[string]string{}
	for _, p := range paths {
		s, err := LoadScenario(p)
		if err != nil {
			return nil, err
		}
		if prev, ok := seen[s.ID]; ok {
			return nil, fmt.Errorf("场景 ID 重复: %s（%s 与 %s）", s.ID, prev, p)
		}
		seen[s.ID] = p
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s 下没有场景 JSON", dir)
	}
	return out, nil
}

// Validate 拒绝会让评分产生歧义的 manifest。
func (s *Scenario) Validate() error {
	if strings.TrimSpace(s.ID) == "" {
		return fmt.Errorf("id 不能为空")
	}
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("name 不能为空")
	}
	if strings.TrimSpace(s.Goal) == "" {
		return fmt.Errorf("goal 不能为空")
	}
	if len(s.Expected) == 0 {
		return fmt.Errorf("expected 至少要有 1 条 ground truth")
	}
	for i, e := range s.Expected {
		if strings.TrimSpace(e.VulnClass) == "" {
			return fmt.Errorf("expected[%d].vulnclass 不能为空", i)
		}
		if e.MinEvidenceRunes < -1 {
			return fmt.Errorf("expected[%d].min_evidence_runes 不能小于 -1", i)
		}
	}
	if s.MaxMinutes < 0 || s.MaxUSD < 0 {
		return fmt.Errorf("预算字段不能为负")
	}
	return nil
}

// RequiredCount 返回参与 pass 判定的预期项数量。
func (s *Scenario) RequiredCount() int {
	n := 0
	for _, e := range s.Expected {
		if !e.Optional {
			n++
		}
	}
	return n
}
