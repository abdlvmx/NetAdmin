//go:build !windows

package main

// runTask на не-Windows не поддерживается (заглушка).
func runTask(kind, payload string) (status, output string, code int) {
	return "failed", "удалённые задачи поддерживаются только на Windows", 1
}
