//go:build !windows

package main

import "os/exec"

func prepareProcessTree(cmd *exec.Cmd) (func() error, func(), error) {
	return func() error { return nil }, func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}, nil
}
