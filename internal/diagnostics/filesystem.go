package diagnostics

import (
	"context"
	"errors"
	"time"
)

// Timeout is shared by configuration, SQL queries and filesystem checks in a
// report. Filesystem syscalls cannot be interrupted reliably (for example UNC).
const Timeout = 3 * time.Second

var (
	ErrFilesystemBusy        = errors.New("diagnostic filesystem check already running")
	ErrFilesystemTimeout     = errors.New("diagnostic filesystem check timed out")
	ErrFilesystemUnavailable = errors.New("diagnostic filesystem check unavailable")
)

type filesystemGate struct{ active chan struct{} }

// One global gate covers both settings and backup checks. A timed-out syscall
// retains its slot until it actually returns; later requests do not spawn or
// queue workers behind it. Its result channel is buffered so the worker can
// finish and release the gate even after the requesting client has gone away.
var diagnosticFilesystem = &filesystemGate{active: make(chan struct{}, 1)}

type filesystemResult[T any] struct {
	value T
	err   error
}

func Filesystem[T any](ctx context.Context, work func() (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	return runFilesystem(ctx, diagnosticFilesystem, work)
}

func runFilesystem[T any](ctx context.Context, gate *filesystemGate, work func() (T, error)) (T, error) {
	var zero T
	if ctx.Err() != nil {
		return zero, ErrFilesystemTimeout
	}
	select {
	case gate.active <- struct{}{}:
	default:
		return zero, ErrFilesystemBusy
	}
	if ctx.Err() != nil {
		<-gate.active
		return zero, ErrFilesystemTimeout
	}
	result := make(chan filesystemResult[T], 1)
	go func() {
		var outcome filesystemResult[T]
		func() {
			defer func() {
				if recover() != nil {
					outcome.err = ErrFilesystemUnavailable
				}
			}()
			outcome.value, outcome.err = work()
		}()
		<-gate.active
		result <- outcome
	}()
	select {
	case outcome := <-result:
		if ctx.Err() != nil {
			return zero, ErrFilesystemTimeout
		}
		return outcome.value, outcome.err
	case <-ctx.Done():
		return zero, ErrFilesystemTimeout
	}
}
