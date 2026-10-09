//go:build !windows

package main

import "context"

// runTask на не-Windows не поддерживается (заглушка).
func runPlatformTask(_ context.Context, kind, payload string) (status, output string, code int) {
	return "failed", "удалённые задачи поддерживаются только на Windows", 1
}
