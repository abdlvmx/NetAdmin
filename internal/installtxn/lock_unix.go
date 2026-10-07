//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package installtxn

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func lock(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, ".netadmin-install.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
