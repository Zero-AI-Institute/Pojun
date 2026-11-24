package pricing

import "testing"

func TestEstimate(t *testing.T) {
	cases := []struct {
		model   string
		in, out int64
		want    float64
		known   bool
	}{
		{"claude-sonnet-4", 1_000_000, 1_000_000, 18, true},
		{"gpt-5.1", 1_000_000, 1_000_000, 11.25, true},
		{"some-model:free", 1_000_000, 1_000_000, 0, true},
		{"unknown-model", 1_000_000, 1_000_000, 0, false},
	}
	for _, c := range cases {
		got, known := Estimate(c.model, c.in, c.out)
		if known != c.known || (known && got != c.want) {
			t.Errorf("Estimate(%s) = %v/%v, want %v/%v", c.model, got, known, c.want, c.known)
		}
	}
}
