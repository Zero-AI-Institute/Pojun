package db

import (
	"strings"
	"testing"
)

func TestFindingDedupKeysIdempotency(t *testing.T) {
	in := RecordFindingInput{
		VulnClass: "sqli",
		Name:      "Union SQLi",
		Summary:   "GET https://x.test/api/user?id=1 union select",
		Parameter: "id",
	}
	var got string
	for _, k := range FindingDedupKeys(in, "") {
		if k.Kind == FindingKeyIdem {
			got = k.Key
		}
	}
	if !strings.HasPrefix(got, "idem:注入:x.test/api/user:id") {
		t.Fatalf("idem key=%q", got)
	}
}
