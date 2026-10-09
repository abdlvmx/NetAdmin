//go:build !securityevents || !windows

package main

import "context"

func startEventWorker(context.Context) {}
