package agent

import "testing"

// The exported constant is what the task egress receipt (issue #39) declares to
// users; the actual default applied by http_request lives as a literal in
// tools_http.go (existing js_audit tests read it back from source). This guards
// the two copies from drifting.
func TestDefaultTargetUserAgentMatchesToolsHTTP(t *testing.T) {
	got := platformDefaultUA(t)
	if DefaultTargetUserAgent != got {
		t.Fatalf("DefaultTargetUserAgent = %q，tools_http.go 实际默认 = %q", DefaultTargetUserAgent, got)
	}
	if !chromeUARe.MatchString(DefaultTargetUserAgent) {
		t.Fatalf("默认 UA 不是合法 Chrome 形态: %q", DefaultTargetUserAgent)
	}
}
