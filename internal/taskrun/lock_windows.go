//go:build windows

package taskrun

import (
	"os"
	"sync"

	"golang.org/x/sys/windows"
)

func lockJournal(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	overlapped := &windows.Overlapped{}
	h := windows.Handle(f.Fd())
	if err = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped); err != nil {
		f.Close()
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(func() { windows.UnlockFileEx(h, 0, 1, 0, overlapped); f.Close() }) }, nil
}
