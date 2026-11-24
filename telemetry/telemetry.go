// Package telemetry is the smallest useful OpenTelemetry wiring for Pojun.
//
// Default is a pure no-op: without OTEL_TRACES_EXPORTER=otlp (and an endpoint)
// the global tracer provider stays the OTel no-op provider, so existing
// deployments pay no network cost. When enabled, planner/worker/main-agent runs
// and every tool call become spans; export is OTLP/HTTP (standard
// OTEL_EXPORTER_OTLP_ENDPOINT / OTEL_EXPORTER_OTLP_TRACES_ENDPOINT env).
package telemetry

import (
	"context"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/chu0119/pojun"

var (
	initOnce sync.Once
	enabled  bool
)

// Init installs the OTLP/HTTP tracer provider when explicitly enabled. Safe to
// call repeatedly; later calls are no-ops.
func Init(ctx context.Context) {
	initOnce.Do(func() {
		if strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED")), "true") {
			return
		}
		exporter := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_EXPORTER")))
		endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))
		if endpoint == "" {
			endpoint = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
		}
		if exporter != "otlp" && endpoint == "" {
			return
		}
		exp, err := otlptracehttp.New(ctx)
		if err != nil {
			return
		}
		res, _ := resource.New(ctx, resource.WithAttributes(
			attribute.String("service.name", "pojun"),
			attribute.String("service.version", os.Getenv("POJUN_VERSION")),
		))
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(res),
			sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(1))),
		)
		otel.SetTracerProvider(tp)
		enabled = true
	})
}

// Enabled reports whether an exporter was installed (diagnostics only).
func Enabled() bool { return enabled }

// Start begins a span. With the default no-op provider this is cheap and safe.
func Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return otel.Tracer(tracerName).Start(ctx, name, trace.WithAttributes(attrs...))
}
