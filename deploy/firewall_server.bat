@echo off
REM ============================================================================
REM  NetAdmin Server — правило брандмауэра Windows для порта панели.
REM  Запускать ОТ ИМЕНИ АДМИНИСТРАТОРА на машине, где работает netadmin.exe.
REM
REM  Канал не шифруется, поэтому порт открывается ТОЛЬКО для локальной сети:
REM  профиль private + ограничение по адресу источника. Сам сервер дополнительно
REM  отсекает запросы из неразрешённых подсетей (NETADMIN_ALLOW).
REM ============================================================================
setlocal

REM --- настройки ---
set "PORT=8765"
REM Источники: LocalSubnet — подсеть машины. Можно указать явно,
REM например: set "REMOTE=192.168.1.0/24,192.168.2.0/24"
set "REMOTE=LocalSubnet"
set "RULE=NetAdmin (LAN)"

echo [1/2] Удаление прежнего правила (если было) ...
netsh advfirewall firewall delete rule name="%RULE%" >nul 2>&1

echo [2/2] Создание правила: TCP %PORT%, профиль private, источники %REMOTE% ...
netsh advfirewall firewall add rule ^
  name="%RULE%" ^
  dir=in action=allow protocol=TCP localport=%PORT% ^
  profile=private ^
  remoteip=%REMOTE% >nul

if errorlevel 1 (
  echo ОШИБКА: не удалось создать правило. Запустите файл от имени администратора.
  exit /b 1
)

echo.
echo Готово. Порт %PORT% открыт только для %REMOTE% в профиле private.
echo Проверить:  netsh advfirewall firewall show rule name="%RULE%"
echo Удалить:    netsh advfirewall firewall delete rule name="%RULE%"
echo.
echo ВАЖНО: убедитесь, что сетевое подключение отнесено к профилю
echo "Частная сеть", иначе правило не применится.
endlocal
