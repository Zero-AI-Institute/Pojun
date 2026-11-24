package db

import "testing"

func TestIntentReflectionRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	expID, err := d.CreateExploration("reflection test", "test")
	if err != nil {
		t.Fatal(err)
	}
	st := d.Exploration(expID)
	intentID, err := st.AddIntent(map[string]any{"summary": "probe authz", "dimension": "authz"}, 5, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	r := IntentReflection{
		IntentID: intentID, Dimension: "authz", TerminalState: "exhausted",
		TerminalReason: "max_turns", WroteBack: 0, ToolCalls: 9, ToolErrors: 2,
		Summary: "probe authz", Lesson: "first lesson", AssetIDs: []int64{},
	}
	if err := st.RecordIntentReflection(r); err != nil {
		t.Fatal(err)
	}
	list, err := st.RecentReflections(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Lesson != "first lesson" || list[0].ToolCalls != 9 {
		t.Fatalf("reflections = %+v", list)
	}
	// upsert same intent → one row, updated lesson
	r.Lesson = "second lesson"
	r.ToolCalls = 10
	if err := st.RecordIntentReflection(r); err != nil {
		t.Fatal(err)
	}
	list, _ = st.RecentReflections(5)
	if len(list) != 1 || list[0].Lesson != "second lesson" || list[0].ToolCalls != 10 {
		t.Fatalf("upsert failed: %+v", list)
	}
	// dimension filter
	byDim, err := st.ReflectionsForDimension("authz", 5)
	if err != nil || len(byDim) != 1 {
		t.Fatalf("byDim=%+v err=%v", byDim, err)
	}
	if byDim[0].IntentID != intentID {
		t.Fatalf("intent id = %d", byDim[0].IntentID)
	}
}
