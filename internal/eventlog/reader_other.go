//go:build securityevents && !windows

package eventlog

import (
	"context"
	"errors"
)

// Read is unavailable outside Windows; an unsupported host is not an empty log.
func Read(ctx context.Context, channel string, cursor Cursor, limit int) (ReadResult, error) {
	if err := ctx.Err(); err != nil {
		return ReadResult{}, err
	}
	return ReadResult{}, errors.New("Windows Event Log collection is available only on Windows")
}
