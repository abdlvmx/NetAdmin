@echo off
REM ============================================================================
REM  NetAdmin Server — правило брандмауэра Windows для порта панели.
REM  Запускать ОТ ИМЕНИ АДМИНИСТРАТОРА на машине, где работает netadmin.exe.
REM
REM  Канал не шифруется, поэтому порт открывается ТОЛЬКО для локальной сети:
REM  ограничение по профилю и по адресу источника. Сам сервер дополнительно
REM  отсекает запросы из неразрешённых подсетей (NETADMIN_ALLOW).
REM ============================================================================
setlocal

REM --- настройки ---
set "PORT=8765"

REM Источники. LocalSubnet — только подсеть самой машины.
REM Если сотрудники ходят с телефонов через Wi-Fi в ДРУГОЙ подсети, её нужно
REM добавить явно, иначе брандмауэр отсечёт их запросы:
REM   set "REMOTE=LocalSubnet,192.168.50.0/24"
set "REMOTE=LocalSubnet"

REM Профиль сети, к которому применяется правило. Windows относит подключение
REM к «Частной» или «Общедоступной» сети; правило для private в общедоступной
REM сети не действует. Значение any покрывает оба, но в общедоступной сети порт
REM будет открыт и для случайных соседей по сегменту — используйте осознанно.
set "PROFILE=private"

set "RULE=NetAdmin (LAN)"

echo [1/3] Проверка профиля сетевых подключений ...
powershell -NoProfile -Command ^
  "$p=Get-NetConnectionProfile ^| Select-Object -ExpandProperty NetworkCategory;" ^
  "if ($p -notcontains 'Private' -and '%PROFILE%' -eq 'private') {" ^
  "  Write-Host '';" ^
  "  Write-Host 'ВНИМАНИЕ: ни одно подключение не отнесено к Частной сети.';" ^
  "  Write-Host 'Правило для профиля private создастся, но применяться не будет.';" ^
  "  Write-Host 'Откройте Параметры - Сеть и Интернет - Свойства подключения';" ^
  "  Write-Host 'и выберите Частная сеть, либо задайте PROFILE=any в этом файле.';" ^
  "  Write-Host '';" ^
  "}" 2>nul

echo [2/3] Удаление прежнего правила (если было) ...
netsh advfirewall firewall delete rule name="%RULE%" >nul 2>&1

echo [3/3] Создание правила: TCP %PORT%, профиль %PROFILE%, источники %REMOTE% ...
netsh advfirewall firewall add rule ^
  name="%RULE%" ^
  dir=in action=allow protocol=TCP localport=%PORT% ^
  profile=%PROFILE% ^
  remoteip=%REMOTE% >nul

if errorlevel 1 (
  echo ОШИБКА: не удалось создать правило. Запустите файл от имени администратора.
  exit /b 1
)

echo.
echo Готово. Порт %PORT% открыт для %REMOTE% в профиле %PROFILE%.
echo Проверить:  netsh advfirewall firewall show rule name="%RULE%"
echo Удалить:    netsh advfirewall firewall delete rule name="%RULE%"
endlocal
