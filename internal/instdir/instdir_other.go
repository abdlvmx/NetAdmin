//go:build !windows

package instdir

// Заглушка для сборки под другие ОС: продукт кросс-компилируется, но каталог
// установки и права на него — вещи Windows (см. internal/winsvc).

func Secure(string) (bool, error) { return false, ErrUnsupported }
