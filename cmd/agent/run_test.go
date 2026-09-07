package main

import (
	"testing"
	"time"
)

// Отсутствие ключа регистрации не должно гасить процесс.
//
// Прежде агент печатал строку и звал os.Exit(1). Под службой это смерть без
// отчёта диспетчеру: в журнале остаётся «terminated unexpectedly», а
// настроенные действия восстановления дают цикл перезапусков — агент
// поднимается, снова не находит ключа, снова умирает, и так до вмешательства.
func TestRunWithoutEnrollKeyReturnsError(t *testing.T) {
	savedEnroll, savedDevice, savedID := token, deviceToken, deviceID
	t.Cleanup(func() { token, deviceToken, deviceID = savedEnroll, savedDevice, savedID })
	token, deviceToken, deviceID = "", "", 0

	done := make(chan error, 1)
	go func() { done <- run(nil) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("агент без ключа регистрации завершился без ошибки")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run не вернулся: агент без ключа ушёл в рабочий цикл")
	}
}
