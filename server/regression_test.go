package server

import (
	"strings"
	"testing"
)

func TestParseRawHTTPRequest(t *testing.T) {
	raw := "POST /api/x?y=1 HTTP/1.1\r\nHost: example.com\r\nCookie: a=b\r\nContent-Type: application/json\r\n\r\n{\"k\":1}"
	method, target, headers, body := parseRawHTTPRequest(raw)
	if method != "POST" || target != "/api/x?y=1" {
		t.Fatalf("line = %s %s", method, target)
	}
	if headers.Get("Host") != "example.com" || headers.Get("Cookie") != "a=b" {
		t.Fatalf("headers = %+v", headers)
	}
	if strings.TrimSpace(body) != `{"k":1}` {
		t.Fatalf("body = %q", body)
	}
}

func TestSafeReplayMethod(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "", "OPTIONS"} {
		if !safeReplayMethod(m) {
			t.Errorf("%q should be safe", m)
		}
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if safeReplayMethod(m) {
			t.Errorf("%q must require allow_write", m)
		}
	}
}
