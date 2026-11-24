package telemetry

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

func TestStartNoopDefault(t *testing.T) {
	ctx, span := Start(context.Background(), "test", attribute.String("k", "v"))
	if ctx == nil || span == nil {
		t.Fatal("span/context must not be nil")
	}
	span.End()
}
