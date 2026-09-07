//go:build !windows

package main

import (
	"fmt"

	"netadmin/internal/wincon"
)

// Console-помощники общие с агентом; netsh и профили сетевых подключений
// существуют только в Windows.

func elevateSelf(args ...string) (bool, error) { return wincon.Elevate(args...) }
func ownsConsole() bool                        { return wincon.OwnsConsole() }
func holdWindow()                              { wincon.Hold() }
func askYesNo(q string) bool                   { return wincon.AskYesNo(q) }

func privateProfileActive() bool { return true }

func openFirewallPort(string) error {
	return fmt.Errorf("правила брандмауэра Windows на этой системе не применяются")
}
