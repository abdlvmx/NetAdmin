//go:build !windows

package auth

import "os"

func protectMFAKey(path string) error { return os.Chmod(path, 0600) }
