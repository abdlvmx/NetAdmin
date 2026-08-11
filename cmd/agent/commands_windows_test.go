//go:build windows

package main

import "testing"

// Агент исполняет только ключи из белого списка; неизвестный ключ отклоняется.
func TestRunLibraryCommandWhitelist(t *testing.T) {
	if status, out, _ := runLibraryCommand("__evil__"); status != "failed" {
		t.Fatalf("неизвестная команда должна отклоняться, получено status=%q out=%q", status, out)
	}
	// безопасная команда из библиотеки выполняется
	status, out, code := runLibraryCommand("list_users")
	if status != "done" || code != 0 {
		t.Fatalf("list_users должна выполняться: status=%q code=%d out=%q", status, code, out)
	}
	if out == "" {
		t.Fatal("ожидался непустой вывод list_users")
	}
}

// Ключи белого списка агента должны быть согласованы (непустые скрипты).
func TestAgentCommandsNonEmpty(t *testing.T) {
	for k, v := range agentCommands {
		if k == "" || v == "" {
			t.Fatalf("пустой ключ/скрипт: %q→%q", k, v)
		}
	}
}
