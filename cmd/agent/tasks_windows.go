//go:build windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

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
	case "check":
		return runSelfCheck()
	case "selfupdate":
		return selfUpdate(payload)
	default:
		return "failed", "неизвестная задача: " + kind, 1
	}
}

// runSelfCheck выполняет самодиагностику агента и возвращает её отчёт целиком.
//
// Отдельным процессом, а не вызовом runCheck прямо здесь: проверка перечитывает
// состояние и переприсваивает глобальные deviceToken и deviceID, которыми в это
// же время пользуется рабочий цикл, — в одном процессе это гонка. Заодно отчёт
// получается ровно тем, что увидел бы человек, запустивший agent.exe -check
// руками: одна проверка, а не две расходящиеся.
//
// Ненулевой код — это найденные проблемы, а не сорванная задача: диагностика
// отработала и ответила. Он возвращается как есть, чтобы на сервере было видно,
// чем она кончилась.
func runSelfCheck() (string, string, int) {
	exe, err := os.Executable()
	if err != nil {
		return "failed", "не удалось определить путь к агенту: " + err.Error(), 1
	}
	cmd := exec.Command(exe, "-check")
	hideWindow(cmd)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		return "failed", "самодиагностика не запустилась: " + err.Error(), 1
	}
	return "done", strings.TrimSpace(out.String()), code
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
