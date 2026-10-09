//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/windows"
)

// runPlatformTask выполняет разрешённое действие с общим сроком и отменой.
func runPlatformTask(ctx context.Context, kind, payload string) (status, output string, code int) {
	switch kind {
	case "reboot":
		return runShutdownContext(ctx, "/r")
	case "shutdown":
		return runShutdownContext(ctx, "/s")
	case "logoff":
		out, err := logoffActiveSession()
		if err != nil {
			return "failed", "logoff: " + err.Error(), 1
		}
		return "done", out, 0
	case "command":
		return runLibraryCommandContext(ctx, payload)
	case "install":
		return installPackageContext(ctx, payload)
	case "check":
		return runSelfCheckContext(ctx)
	case "selfupdate":
		return selfUpdateContext(ctx, payload)
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
// Ненулевой код и подробный отчёт сохраняются, чтобы найденные проблемы были
// видны в истории действий. Проверка ограничена временем и может быть отменена.
func runSelfCheck() (string, string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), taskTimeout("check", ""))
	defer cancel()
	return runSelfCheckContext(ctx)
}

func runSelfCheckContext(ctx context.Context) (string, string, int) {
	exe, err := os.Executable()
	if err != nil {
		return "failed", "не удалось определить путь к агенту: " + err.Error(), 1
	}
	cmd := exec.Command(exe, "-check")
	out := runProcess(ctx, cmd)
	return out.Status, out.Output, out.ExitCode
}

// runShutdown планирует перезагрузку (/r) или выключение (/s) с предупреждением
// пользователю за 30 секунд. Windows подразумевает /f при положительном /t.
func runShutdown(flag string) (string, string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), taskTimeout("shutdown", ""))
	defer cancel()
	return runShutdownContext(ctx, flag)
}

func runShutdownContext(ctx context.Context, flag string) (string, string, int) {
	cmd := exec.Command("shutdown", flag, "/t", "30", "/c", "Действие администратора через NetAdmin")
	out := runProcess(ctx, cmd)
	if out.Status != "done" {
		return out.Status, out.Output, out.ExitCode
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
	// Do not block the task worker waiting for applications in the user session.
	r, _, err := procLogoffSession.Call(0, sid, 0)
	if r == 0 {
		return "", err
	}
	return "запрошено завершение сессии пользователя", nil
}
