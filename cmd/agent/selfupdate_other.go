//go:build !windows

package main

// Самообновление реализовано только для Windows: на прочих ОС агент шлёт
// лишь метрики и удалённых задач не выполняет (см. tasks_other.go).

var restartPending bool

func cleanupOldBinary()     {}
func restartIntoNewBinary() {}
