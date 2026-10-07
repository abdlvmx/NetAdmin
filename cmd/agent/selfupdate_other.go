//go:build !windows

package main

// Самообновление реализовано только для Windows: на прочих ОС агент шлёт
// лишь метрики и удалённых задач не выполняет (см. tasks_other.go).

func cleanupOldBinary()                           {}
func launchPendingUpdate(int64) (bool, error)     { return false, nil }
func runUpdateHelperCommand([]string) (bool, int) { return false, 0 }
func flushUpdateResult()                          {}
