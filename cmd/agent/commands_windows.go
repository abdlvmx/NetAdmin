//go:build windows

package main

import (
	"context"
	"os/exec"
)

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
	"winupdate_scan":    `$p = Start-Process -FilePath UsoClient -ArgumentList 'StartScan' -NoNewWindow -Wait -PassThru -ErrorAction Stop; if ($p.ExitCode -ne 0) { throw ('UsoClient завершился с кодом ' + $p.ExitCode) }; 'Запрос поиска обновлений отправлен Windows'`,
	"gpupdate":          `gpupdate /force`,
}

// runLibraryCommand исполняет команду из белого списка по ключу.
func runLibraryCommand(key string) (status, output string, code int) {
	ctx, cancel := context.WithTimeout(context.Background(), taskTimeout("command", key))
	defer cancel()
	return runLibraryCommandContext(ctx, key)
}

func runLibraryCommandContext(ctx context.Context, key string) (status, output string, code int) {
	script, ok := agentCommands[key]
	if !ok {
		return "failed", "команда не разрешена: " + key, 1
	}
	// Native exit codes and terminating PowerShell errors must survive the shell.
	wrapped := psUTF8 + `$ErrorActionPreference='Stop'; try { & { ` + script + ` }; if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE } } catch { [Console]::Error.WriteLine($_.ToString()); exit 1 }`
	out := runProcess(ctx, exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", wrapped))
	return out.Status, out.Output, out.ExitCode
}
