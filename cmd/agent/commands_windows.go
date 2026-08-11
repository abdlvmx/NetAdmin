//go:build windows

package main

import "strings"

// agentCommands — БЕЛЫЙ СПИСОК команд. Агент исполняет только эти ключи; ничего
// произвольного с сервера выполнить нельзя (ключи должны совпадать с библиотекой
// сервера internal/handlers/commands.go).
var agentCommands = map[string]string{
	"flushdns":          `ipconfig /flushdns`,
	"ipconfig":          `ipconfig /all`,
	"systeminfo":        `systeminfo`,
	"list_users":        `(Get-CimInstance Win32_ComputerSystem).UserName`,
	"restart_spooler":   `Restart-Service Spooler -Force; 'Служба печати перезапущена'`,
	"clear_print_queue": `Stop-Service Spooler -Force; Remove-Item "$env:WINDIR\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue; Start-Service Spooler; 'Очередь печати очищена'`,
	"clear_temp":        `Remove-Item "$env:TEMP\*","$env:WINDIR\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue; 'Временные файлы очищены'`,
	"restart_dnscache":  `Restart-Service Dnscache -Force; 'DNS-клиент перезапущен'`,
	"restart_explorer":  `Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; 'Проводник перезапущен (перезапустится автоматически)'`,
	"winupdate_scan":    `try { Start-Process -FilePath UsoClient -ArgumentList 'StartScan' -NoNewWindow -ErrorAction Stop; 'Поиск обновлений запущен' } catch { 'UsoClient недоступен на этой системе' }`,
	"gpupdate":          `gpupdate /force`,
}

// runLibraryCommand исполняет команду из белого списка по ключу.
func runLibraryCommand(key string) (status, output string, code int) {
	script, ok := agentCommands[key]
	if !ok {
		return "failed", "команда не разрешена: " + key, 1
	}
	out, ok := runPS(script)
	if !ok {
		return "failed", "ошибка выполнения команды", 1
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		s = "выполнено"
	}
	if len(s) > 6000 {
		s = s[:6000] + "…"
	}
	return "done", s, 0
}
