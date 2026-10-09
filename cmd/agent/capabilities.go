package main

import (
	"netadmin/internal/edition"
	"runtime"
)

func agentCapabilities() []string {
	caps := []string{"task_protocol_2"}
	if edition.Events && runtime.GOOS == "windows" {
		caps = append(caps, "security_events_v1")
	}
	return caps
}
