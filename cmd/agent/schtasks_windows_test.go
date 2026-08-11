//go:build windows

package main

import "testing"

// Проверяет, что сбор задач планировщика работает на реальной системе.
func TestCollectScheduledTasksReal(t *testing.T) {
	ts := collectScheduledTasks()
	t.Logf("найдено задач планировщика: %d", len(ts))
	if len(ts) == 0 {
		t.Skip("задач не найдено (возможно, ограничение окружения) — пропуск")
	}
	for _, e := range ts {
		if name, _ := e["name"].(string); name == "" {
			t.Fatalf("задача с пустым именем: %+v", e)
		}
		if _, ok := e["action"]; !ok {
			t.Fatalf("нет поля action: %+v", e)
		}
	}
}
