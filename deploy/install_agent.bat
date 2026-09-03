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

REM --- проверка настроек ---
REM Скрипт запускают на каждой машине, и незаполненный шаблон легко пропустить:
REM заглушки молча уезжали в машинные переменные, агент вставал, но подключиться
REM не мог, а на экране всё выглядело успешно. Лучше отказаться сразу.
if "%SERVER_URL%"=="YOUR_URL_HERE" (
  echo.
  echo ОШИБКА: не заполнен SERVER_URL в начале этого файла.
  echo Откройте install_agent.bat блокнотом и впишите адрес сервера, например:
  echo     set "SERVER_URL=http://192.168.1.10:8765"
  echo Адрес сервер печатает в журнале при запуске.
  exit /b 1
)
if "%ENROLL_TOKEN%"=="YOUR_TOKEN_HERE" (
  echo.
  echo ОШИБКА: не заполнен ENROLL_TOKEN в начале этого файла.
  echo Скопируйте токен агента со страницы Настройки на сервере и впишите:
  echo     set "ENROLL_TOKEN=токен_со_страницы_настроек"
  exit /b 1
)
if "%SERVER_URL%"=="" (
  echo ОШИБКА: SERVER_URL пуст.
  exit /b 1
)

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
