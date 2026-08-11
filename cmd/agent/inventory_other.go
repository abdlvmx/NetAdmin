//go:build !windows

package main

// На не-Windows инвентарь ПО, службы, автозагрузка и задачи не собираются (заглушки).
func collectSoftware() []map[string]any       { return nil }
func collectServices() []map[string]any       { return nil }
func collectAutoruns() []map[string]any       { return nil }
func collectScheduledTasks() []map[string]any { return nil }
func collectDisks() []map[string]any          { return nil }
