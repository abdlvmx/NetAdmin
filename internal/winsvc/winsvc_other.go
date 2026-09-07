//go:build !windows

package winsvc

// Заглушки для сборки под другие ОС: продукт кросс-компилируется, но службы
// Windows там неприменимы.

func IsService() bool { return false }
func Elevated() bool  { return false }

func Install(Config) error   { return ErrUnsupported }
func Uninstall(string) error { return ErrUnsupported }
func Stop(string) error      { return ErrUnsupported }
func Restart(string) error   { return ErrUnsupported }

func State(string) (string, error) { return "", ErrUnsupported }

func Run(string, func(stop <-chan struct{})) error { return ErrUnsupported }
