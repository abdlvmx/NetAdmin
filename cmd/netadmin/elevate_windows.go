//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"

	"netadmin/internal/wincon"
)

// Запуск двойным щелчком.
//
// Установка требует прав администратора, и раньше `-install` без них просто
// отказывался с подсказкой «откройте PowerShell от имени администратора».
// Для человека, который скачал один .exe, это лишний шаг: Windows умеет
// спросить сама. Поэтому процесс перезапускает себя через ShellExecuteW с
// глаголом «runas» — тот же запрос UAC, что у обычных установщиков, и без
// манифеста в ресурсах, для которого понадобился бы внешний инструмент сборки.

// Console-помощники и запрос прав живут в общем пакете: тем же самым
// пользуется агент, и держать две копии одного кода незачем.
func elevateSelf(args ...string) (bool, error) { return wincon.Elevate(args...) }
func ownsConsole() bool                        { return wincon.OwnsConsole() }
func holdWindow()                              { wincon.Hold() }
func askYesNo(q string) bool                   { return wincon.AskYesNo(q) }

// openFirewallPort создаёт правило для порта панели: только профиль «Частная
// сеть» и только локальная подсеть.
//
// Повторяет deploy/firewall_server.bat намеренно теми же параметрами: канал не
// шифруется, и открывать порт шире локального сегмента нельзя. Прежнее правило
// сначала удаляется, иначе повторная установка накопила бы дубли.
func openFirewallPort(port string) error {
	const rule = "NetAdmin (LAN)"

	del := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+rule)
	_ = del.Run() // правила могло не быть — обычный случай

	add := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+rule, "dir=in", "action=allow", "protocol=TCP",
		"localport="+port, "profile=private", "remoteip=LocalSubnet")
	if out, err := add.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// privateProfileActive сообщает, есть ли подключение, отнесённое к «Частной
// сети». Правило для профиля private в общедоступной сети не действует, и
// молчать об этом нельзя: порт будет «открыт», а агенты не подключатся.
func privateProfileActive() bool {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-NetConnectionProfile).NetworkCategory").Output()
	if err != nil {
		return true // не смогли выяснить — не пугаем зря
	}
	return strings.Contains(string(out), "Private")
}
