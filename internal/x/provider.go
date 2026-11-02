package x

import (
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/vladmsnk/doorward/schema"
)

// LoggerProvider gives the box's logger.
type LoggerProvider interface {
	Logger() *slog.Logger
}

// TracerProvider gives the tracer spans are started with; a no-op one when
// tracing is off.
type TracerProvider interface {
	Tracer() trace.Tracer
}

// ClockProvider gives the time, so tests can stand the box's clock still.
type ClockProvider interface {
	Now() time.Time
}

// ValidatorProvider gives the contract's schema validator.
type ValidatorProvider interface {
	Validator() *schema.Validator
}
