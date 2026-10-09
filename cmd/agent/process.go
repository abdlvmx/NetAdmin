package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"netadmin/internal/taskrun"
)

type limitedOutput struct {
	mu        sync.Mutex
	b         []byte
	limit     int
	truncated bool
}

func (w *limitedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	remaining := w.limit - len(w.b)
	if n > remaining {
		w.truncated = true
		p = p[:remaining]
	}
	w.b = append(w.b, p...)
	return n, nil
}
func (w *limitedOutput) String() string {
	return strings.TrimSpace(strings.TrimPrefix(strings.ToValidUTF8(string(w.b), "�"), "\ufeff"))
}

// runProcess owns the entire process tree, bounds both streams, and always waits.
// It never interpolates a server-supplied command line into a shell.
func runProcess(ctx context.Context, cmd *exec.Cmd) taskrun.Outcome {
	stdout := &limitedOutput{limit: 4000}
	stderr := &limitedOutput{limit: 2000}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	hideWindow(cmd)
	start, closeTree, err := prepareProcessTree(cmd)
	if err != nil {
		return taskrun.Outcome{Status: "failed", Output: "Подготовка процесса: " + err.Error(), ExitCode: 1}
	}
	defer closeTree()
	if err = ctx.Err(); err != nil {
		return taskrun.Outcome{Status: "cancelled", Output: "Задача отменена до запуска.", ExitCode: 125}
	}
	if err = cmd.Start(); err != nil {
		return taskrun.Outcome{Status: "failed", Output: "Процесс не запустился: " + err.Error(), ExitCode: 1}
	}
	if err = start(); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return taskrun.Outcome{Status: "failed", Output: "Запуск процесса: " + err.Error(), ExitCode: 1}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var stopErr error
	select {
	case err = <-done:
	case <-ctx.Done():
		stopErr = ctx.Err()
		closeTree()
		_ = cmd.Process.Kill()
		err = <-done
	}
	out := stdout.String()
	if s := stderr.String(); s != "" {
		if out != "" {
			out += "\n\n"
		}
		out += "Ошибки:\n" + s
	}
	if stdout.truncated || stderr.truncated {
		out += "\n[Вывод сокращён]"
	}
	code, status := 0, "done"
	switch {
	case errors.Is(stopErr, context.DeadlineExceeded):
		status, code = "failed", 124
		out += "\nПревышено время выполнения; процесс остановлен."
	case stopErr != nil:
		status, code = "cancelled", 125
		out += "\nВыполнение отменено; процесс остановлен."
	case err != nil:
		status, code = "failed", 1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else {
			out += "\n" + err.Error()
		}
	}
	if strings.TrimSpace(out) == "" {
		out = fmt.Sprintf("Выполнение завершено (код %d).", code)
	}
	return taskrun.Outcome{Status: status, Output: taskrun.LimitOutput(strings.TrimSpace(out)), ExitCode: code}
}

func runTaskContext(ctx context.Context, kind, payload string) taskrun.Outcome {
	ctx, cancel := context.WithTimeout(ctx, taskTimeout(kind, payload))
	defer cancel()
	if ctx.Err() != nil {
		return taskrun.Outcome{Status: "cancelled", Output: "Задача отменена до запуска.", ExitCode: 125}
	}
	status, out, code := runPlatformTask(ctx, kind, payload)
	if status == "failed" && ctx.Err() != nil && code != 124 && code != 125 {
		if errors.Is(ctx.Err(), context.Canceled) {
			status, code = "cancelled", 125
		} else {
			code = 124
			out += "\nПревышено время выполнения."
		}
	}
	return taskrun.Outcome{Status: status, Output: out, ExitCode: code}
}

func runTask(kind, payload string) (string, string, int) {
	out := runTaskContext(context.Background(), kind, payload)
	return out.Status, out.Output, out.ExitCode
}

func taskTimeout(kind, payload string) time.Duration {
	if kind == "install" || kind == "selfupdate" {
		return 45 * time.Minute
	}
	if kind == "command" && payload == "gpupdate" {
		return 5 * time.Minute
	}
	if kind == "command" {
		return 2 * time.Minute
	}
	return 30 * time.Second
}

var _ io.Writer = (*limitedOutput)(nil)
