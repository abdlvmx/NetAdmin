//go:build windows

package winsvc

import (
	"errors"
	"testing"
)

// Постоянный отказ останавливает службу штатно, а не как аварию.
//
// Windows повторяет последнее из настроенных действий восстановления
// бесконечно, поэтому служба, которую перезапуск не вылечит — неверная
// настройка, отсутствующий ключ регистрации, — поднималась бы раз в минуту с
// одной и той же записью в журнале. Штатная остановка восстановление не
// запускает: причина уже записана, чинить человеку.
func TestPermanentFailureStopsCleanly(t *testing.T) {
	h := &handler{err: Permanent(errors.New("не задан ключ регистрации"))}
	svcSpecific, code := h.exitCode()
	if svcSpecific || code != 0 {
		t.Errorf("постоянный отказ дал (%v, %d), ожидалась штатная остановка (false, 0)", svcSpecific, code)
	}
}

// Обычная авария остаётся аварией: её перезапуск как раз лечит, ради этого
// служба и выбрана вместо задачи планировщика.
func TestCrashIsReportedAsFailure(t *testing.T) {
	h := &handler{err: errors.New("порт занят")}
	svcSpecific, code := h.exitCode()
	if !svcSpecific || code == 0 {
		t.Errorf("авария дала (%v, %d), ожидался ненулевой код, специфичный для службы", svcSpecific, code)
	}
}

// Остановка по команде — не отказ.
func TestCleanStopHasNoError(t *testing.T) {
	h := &handler{}
	if svcSpecific, code := h.exitCode(); svcSpecific || code != 0 {
		t.Errorf("штатная остановка дала (%v, %d)", svcSpecific, code)
	}
}

// Пометка не должна менять текст: он написан для человека, и приписка про
// перезапуск в нём лишняя.
func TestPermanentKeepsTheMessage(t *testing.T) {
	inner := errors.New("разрешённые подсети: не удалось разобрать 10.0.0")
	wrapped := Permanent(inner)
	if wrapped.Error() != inner.Error() {
		t.Errorf("текст изменился: %q вместо %q", wrapped.Error(), inner.Error())
	}
	if !IsPermanent(wrapped) {
		t.Error("пометка потерялась")
	}
	if !errors.Is(wrapped, inner) {
		t.Error("исходная ошибка недоступна через errors.Is")
	}
	if IsPermanent(inner) {
		t.Error("непомеченная ошибка сочтена постоянной")
	}
	if Permanent(nil) != nil {
		t.Error("Permanent(nil) должен оставаться nil")
	}
}
