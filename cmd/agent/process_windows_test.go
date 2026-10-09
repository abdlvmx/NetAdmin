//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestProcessHelper(t *testing.T) {
	switch os.Getenv("NETADMIN_TEST_PROCESS") {
	case "output":
		fmt.Print(strings.Repeat("вывод ", 2000))
		fmt.Fprint(os.Stderr, "подробная ошибка")
		os.Exit(17)
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$")
		child.Env = append(os.Environ(), "NETADMIN_TEST_PROCESS=child")
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "child":
		_ = os.WriteFile(os.Getenv("NETADMIN_TEST_PID_FILE"), []byte(strconv.Itoa(os.Getpid())), 0600)
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

func TestProcessKeepsStderrExitCodeAndBoundsOutput(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$")
	cmd.Env = append(os.Environ(), "NETADMIN_TEST_PROCESS=output")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := runProcess(ctx, cmd)
	if out.Status != "failed" || out.ExitCode != 17 || !strings.Contains(out.Output, "подробная ошибка") || !strings.Contains(out.Output, "сокращён") || len(out.Output) > 8000 {
		t.Fatalf("outcome: %+v", out)
	}
}

func TestCancellationStopsParentAndChild(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$")
	cmd.Env = append(os.Environ(), "NETADMIN_TEST_PROCESS=parent", "NETADMIN_TEST_PID_FILE="+pidFile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	completed := make(chan struct{})
	go func() {
		defer close(completed)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(pidFile); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
	}()
	out := runProcess(ctx, cmd)
	<-completed
	if out.Status != "cancelled" || out.ExitCode != 125 {
		t.Fatalf("cancellation: %+v", out)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal("child did not start", err)
	}
	pid, _ := strconv.Atoi(string(b))
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err == nil {
		defer windows.CloseHandle(h)
		var code uint32
		if err = windows.GetExitCodeProcess(h, &code); err == nil && code == 259 {
			t.Fatal("child survived cancellation")
		}
	}
}

func TestProcessDeadlineReturnsTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$")
	cmd.Env = append(os.Environ(), "NETADMIN_TEST_PROCESS=child", "NETADMIN_TEST_PID_FILE="+filepath.Join(t.TempDir(), "child.pid"))
	out := runProcess(ctx, cmd)
	if out.Status != "failed" || out.ExitCode != 124 || !strings.Contains(out.Output, "время выполнения") {
		t.Fatalf("deadline: %+v", out)
	}
}

func TestPowerShellFailureIsNotReportedAsSuccess(t *testing.T) {
	const key = "__test_failure"
	agentCommands[key] = `Write-Error 'контрольная ошибка'`
	defer delete(agentCommands, key)
	status, out, code := runLibraryCommand(key)
	if status != "failed" || code != 1 || !strings.Contains(out, "контрольная ошибка") {
		t.Fatalf("%s %d %s", status, code, out)
	}
	agentCommands[key] = `cmd /c exit 23`
	status, out, code = runLibraryCommand(key)
	if status != "failed" || code != 23 {
		t.Fatalf("native exit code lost: %s %d %s", status, code, out)
	}
}
