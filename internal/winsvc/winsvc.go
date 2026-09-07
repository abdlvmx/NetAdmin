// Package winsvc — регистрация и запуск компонентов службами Windows.
//
// Общий для сервера и агента: оба ставятся одинаково и одинаково должны
// переживать перезагрузку и собственное падение. Раньше сервер жил в консольном
// окне (закрыли окно — встал мониторинг), а агент — задачей планировщика,
// которая не поднимает его после аварийного завершения.
//
// На не-Windows все функции возвращают ErrUnsupported: продукт собирается и под
// другие ОС, но службы там свои.
package winsvc

import "errors"

// ErrUnsupported возвращается вне Windows.
var ErrUnsupported = errors.New("службы доступны только в Windows")

// Permanent помечает отказ, который перезапуск не вылечит: неверная настройка,
// отсутствующий ключ регистрации. Служба, вернувшая такую ошибку,
// останавливается штатно — иначе действия восстановления поднимали бы её раз в
// минуту до вмешательства человека, с одной и той же записью в журнале.
//
// Пометка не трогает текст: он уже написан для человека, и приписка про
// перезапуск в нём лишняя.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanent{err}
}

// IsPermanent — отказ помечен как неисправимый перезапуском.
func IsPermanent(err error) bool {
	var p permanent
	return errors.As(err, &p)
}

type permanent struct{ error }

func (p permanent) Unwrap() error { return p.error }

// Config описывает регистрируемую службу.
type Config struct {
	Name        string   // системное имя (без пробелов)
	DisplayName string   // как показывается в services.msc
	Description string   // пояснение там же
	Exe         string   // полный путь к исполняемому файлу
	Args        []string // аргументы запуска
}

// Состояния, которые возвращает State.
const (
	StateRunning      = "работает"
	StateStopped      = "остановлена"
	StateNotInstalled = "не установлена"
)
