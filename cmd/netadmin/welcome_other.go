//go:build !windows

package main

import "fmt"

func startAgentSetup(string) error {
	return fmt.Errorf("агент предназначен для Windows")
}
