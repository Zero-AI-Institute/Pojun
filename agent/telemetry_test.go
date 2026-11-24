package agent

import (
	"context"
	"encoding/json"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTracedToolEmitsSpan(t *testing.T) {
	prev := otel.GetTracerProvider()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	})

	tool := &tracedTool{CoreTool: fakeTool("probe", "probe tool")}
	if _, err := tool.Call(context.Background(), json.RawMessage(`{}`), nil); err != nil {
		t.Fatal(err)
	}
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans = %d, want 1", len(spans))
	}
	sp := spans[0]
	if sp.Name != "execute_tool.probe" {
		t.Fatalf("span name = %q", sp.Name)
	}
	found := false
	for _, a := range sp.Attributes {
		if string(a.Key) == "tool.name" && a.Value.AsString() == "probe" {
			found = true
		}
	}
	if !found {
		t.Fatalf("tool.name attribute missing: %+v", sp.Attributes)
	}
}
