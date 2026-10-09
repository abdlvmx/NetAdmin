//go:build !windows

package taskrun

import (
	"golang.org/x/sys/unix"
	"os"
	"sync"
)

func lockJournal(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }) }, nil
}
