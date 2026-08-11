//go:build windows

package main

import (
	"bytes"
	"fmt"
	"os/exec"

	"golang.org/x/sys/windows"
)

// runTask выполняет удалённую задачу и возвращает статус (done|failed), вывод и код.
// Фаза 1: питание (reboot/shutdown/logoff). Прочие виды добавляются позже.
func runTask(kind, payload string) (status, output string, code int) {
	switch kind {
	case "reboot":
		return runShutdown("/r")
	case "shutdown":
		return runShutdown("/s")
	case "logoff":
		out, err := logoffActiveSession()
		if err != nil {
			return "failed", "logoff: " + err.Error(), 1
		}
		return "done", out, 0
	case "command":
		return runLibraryCommand(payload)
	case "install":
		return installPackage(payload)
	default:
		return "failed", "неизвестная задача: " + kind, 1
	}
}

// runShutdown планирует перезагрузку (/r) или выключение (/s) с предупреждением
// пользователю за 30 секунд (без принудительного закрытия приложений).
func runShutdown(flag string) (string, string, int) {
	cmd := exec.Command("shutdown", flag, "/t", "30", "/c", "Действие администратора через NetAdmin")
	hideWindow(cmd)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		code := 1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		return "failed", out.String() + " " + err.Error(), code
	}
	return "done", "запланировано (через 30 с)", 0
}

var (
	modkernel32       = windows.NewLazySystemDLL("kernel32.dll")
	modwtsapi32       = windows.NewLazySystemDLL("wtsapi32.dll")
	procActiveSession = modkernel32.NewProc("WTSGetActiveConsoleSessionId")
	procLogoffSession = modwtsapi32.NewProc("WTSLogoffSession")
)

// logoffActiveSession завершает активную консольную сессию пользователя через
// WTS API (агент работает под SYSTEM, поэтому `shutdown /l` неприменим).
func logoffActiveSession() (string, error) {
	sid, _, _ := procActiveSession.Call()
	if uint32(sid) == 0xFFFFFFFF {
		return "", fmt.Errorf("нет активной консольной сессии")
	}
	// WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE=0, SessionId, bWait=TRUE)
	r, _, err := procLogoffSession.Call(0, sid, 1)
	if r == 0 {
		return "", err
	}
	return "сессия пользователя завершена", nil
}
