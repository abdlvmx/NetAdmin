//go:build windows

package installtxn

import (
	"golang.org/x/sys/windows"
	"path/filepath"
)

// The handle is released by Windows even if the installer crashes. The empty
// file remains so there is no delete/recreate race with another installer.
func lock(dir string) (func(), error) {
	p, err := windows.UTF16PtrFromString(filepath.Join(dir, ".netadmin-install.lock"))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return func() { _ = windows.CloseHandle(h) }, nil
}
