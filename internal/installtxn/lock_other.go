//go:build !windows && !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package installtxn

import "fmt"

func lock(string) (func(), error) {
	return nil, fmt.Errorf("транзакционная установка не поддерживается на этой ОС")
}
