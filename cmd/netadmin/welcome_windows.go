//go:build windows

package main

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

func startAgentSetup(path string) error {
	file, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	cwd, err := windows.UTF16PtrFromString(filepath.Dir(path))
	if err != nil {
		return err
	}
	// ShellExecute creates the installer's interactive console with usable input.
	// exec.Command's nil standard streams would send its prompts to NUL.
	return windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), file,
		windows.StringToUTF16Ptr("-setup"), cwd, windows.SW_SHOWNORMAL)
}
