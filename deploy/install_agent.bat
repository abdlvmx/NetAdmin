@echo off
REM ============================================================================
REM  NetAdmin Agent — тихая фоновая установка (без окна, автозапуск при загрузке)
REM  Запускать ОТ ИМЕНИ АДМИНИСТРАТОРА. Положите agent.exe рядом с этим .bat.
REM ============================================================================
setlocal

REM --- настройки (можно переопределить переменными окружения или зашить в agent.exe) ---
set "SERVER_URL=YOUR_URL_HERE"
set "ENROLL_TOKEN=YOUR_TOKEN_HERE"

set "DEST=%ProgramData%\NetAdmin"
set "EXE=%DEST%\agent.exe"
set "TASK=NetAdminAgent"

echo [1/4] Копирование агента в %DEST% ...
if not exist "%DEST%" mkdir "%DEST%"
copy /Y "%~dp0agent.exe" "%EXE%" >nul || (echo ОШИБКА: нет agent.exe рядом с .bat & exit /b 1)

echo [2/4] Машинные переменные окружения ...
setx NETADMIN_SERVER_URL "%SERVER_URL%" /M >nul
if defined ENROLL_TOKEN setx NETADMIN_AGENT_TOKEN "%ENROLL_TOKEN%" /M >nul

echo [3/4] Создание задачи автозапуска (SYSTEM, при загрузке, скрыто) ...
schtasks /create /tn "%TASK%" /tr "\"%EXE%\"" /sc onstart /ru SYSTEM /rl HIGHEST /f >nul

echo [4/4] Запуск агента сейчас ...
schtasks /run /tn "%TASK%" >nul

echo.
echo Готово. Агент работает фоново, без окна, перезапускается при загрузке ПК.
echo Состояние: %DEST%\agent_state.json   Задача: %TASK%
endlocal
