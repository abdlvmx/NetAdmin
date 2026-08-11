@echo off
REM ===  NetAdmin Agent — удаление. Запускать ОТ ИМЕНИ АДМИНИСТРАТОРА.  ===
setlocal
set "TASK=NetAdminAgent"
set "DEST=%ProgramData%\NetAdmin"

schtasks /end /tn "%TASK%" 2>nul
schtasks /delete /tn "%TASK%" /f 2>nul
taskkill /im agent.exe /f 2>nul

REM убрать машинные переменные (опционально)
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v NETADMIN_SERVER_URL /f 2>nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v NETADMIN_AGENT_TOKEN /f 2>nul

rmdir /S /Q "%DEST%" 2>nul
echo Агент удалён.
endlocal
