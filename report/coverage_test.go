package report

import (
	"strings"
	"testing"
)

func TestMarkdownCoverageSection(t *testing.T) {
	md := Markdown(Input{
		Title: "t",
		Coverage: &CoverageSection{
			Assets: 10, Tested: 3, Findings: 1,
			Rows: []CoverageRow{{Dimension: "越权/未授权", AssetType: "service", Untested: 5, Samples: "a.example.com"}},
			Note: "未测不等于有漏洞",
		},
	})
	for _, want := range []string{"## 覆盖与排除", "范围内资产：**10**", "已触达：**3**", "越权/未授权", "service", "5", "a.example.com", "未测不等于有漏洞"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q:\n%s", want, md)
		}
	}
}
