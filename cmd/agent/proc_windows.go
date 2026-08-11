//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// hideWindow запускает дочерний процесс (PowerShell) без видимого окна —
// чтобы у пользователя ничего не мелькало при фоновом сборе данных.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}
