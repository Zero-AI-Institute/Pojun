package eval

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// 内置场景随二进制分发：release zip 只带可执行文件与 skills，不会带仓库里的
// eval/scenarios 目录；embed 之后 `pojun-maint bench score --scenario dvwa-sqli-xss`
// 在任意部署上都能直接用，不再依赖手工上传 manifest。
//
//go:embed scenarios/*.json
var builtinScenarios embed.FS

// BuiltinScenarioIDs 返回内置场景 ID（排序后），用于 CLI 提示。
func BuiltinScenarioIDs() []string {
	entries, err := builtinScenarios.ReadDir("scenarios")
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".json")
		if name != e.Name() {
			ids = append(ids, name)
		}
	}
	sort.Strings(ids)
	return ids
}

// BuiltinScenario 按 ID 读取内置场景。
func BuiltinScenario(id string) (*Scenario, error) {
	id = strings.TrimSuffix(strings.TrimSpace(id), ".json")
	if id == "" || strings.ContainsAny(id, `/\`) {
		return nil, fmt.Errorf("内置场景 ID 非法: %q", id)
	}
	b, err := builtinScenarios.ReadFile("scenarios/" + id + ".json")
	if err != nil {
		return nil, fmt.Errorf("内置场景 %q 不存在（可用: %s）", id, strings.Join(BuiltinScenarioIDs(), ", "))
	}
	var sc Scenario
	if err := json.Unmarshal(b, &sc); err != nil {
		return nil, fmt.Errorf("内置场景 %s: %w", id, err)
	}
	if err := sc.Validate(); err != nil {
		return nil, fmt.Errorf("内置场景 %s: %w", id, err)
	}
	return &sc, nil
}

// BuiltinScenarios 读取并校验全部内置场景（ID 唯一）。
func BuiltinScenarios() ([]*Scenario, error) {
	ids := BuiltinScenarioIDs()
	out := make([]*Scenario, 0, len(ids))
	for _, id := range ids {
		sc, err := BuiltinScenario(id)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有内置场景")
	}
	return out, nil
}
