//go:build securityevents && !windows

package eventlog

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedReaderIsAnError(t *testing.T) {
	if _, err := Read(context.Background(), "System", Cursor{}, 10); err == nil {
		t.Fatal("unsupported host was reported as an empty Windows channel")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Read(ctx, "System", Cursor{}, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled reader: %v", err)
	}
}
