# Сборка обычной редакции и NetAdmin Events

Редакции выбираются при компиляции. Обычная сборка не содержит модуля Events;
сборка с тегом Go `securityevents` содержит сервер и агент Events. Сбор событий
в Events выключен по умолчанию: администратор включает его для выбранных ПК
после настройки [HTTPS](https.md). Сбор и отправка событий по HTTP недоступны.
Возможности и ограничения описаны в [документации Events](events.md).

На Windows x64 установите Go версии из `go.mod`. Выполняйте команды PowerShell
из корня репозитория; замените `1.1.0` нужной версией:

```powershell
./scripts/build-windows.ps1 -Version 1.1.0 -Edition all
./scripts/package-windows.ps1 -Version 1.1.0 -Edition standard -DistDir dist/standard
./scripts/package-windows.ps1 -Version 1.1.0 -Edition events -DistDir dist/events
```

| Редакция | EXE | Готовый комплект |
|---|---|---|
| Обычная | `dist/standard/netadmin.exe`, `dist/standard/agent.exe` | `dist/standard/NetAdmin-Windows-x64.zip` |
| Events | `dist/events/netadmin.exe`, `dist/events/agent.exe` | `dist/events/NetAdmin-Events-Windows-x64.zip` |

Каждый ZIP содержит ровно `netadmin.exe`, `agent.exe`, `START-HERE.txt` и
`SHA256SUMS.txt`. Внутренний файл сумм проверяет оба EXE; файл рядом с ZIP
также содержит сумму архива. Локальные базы, настройки и коды подключения
в комплект не включаются.

Параметр `-Edition` у сборки по умолчанию равен `standard`; допустимы также
`events` и `all`. Упаковка без `-Edition` создаёт обычный комплект:

```powershell
./scripts/build-windows.ps1 -Version 1.1.0
./scripts/package-windows.ps1 -Version 1.1.0
```

Обычная упаковка без `-DistDir` использует `dist/standard`. Для совместимости
с прежней ручной сборкой она также принимает EXE из `dist`, если каталога
`dist/standard` нет. Для Events по умолчанию используется `dist/events`.
При указании `-DistDir` упаковщик берёт EXE непосредственно из этого каталога.

Порядок сборки обязателен: сначала агент выбранной редакции, затем его копия
в `internal/agentbin/bin/agent.exe`, затем сервер той же редакции. Сервер
встраивает агент через `go:embed`. Helper выполняет этот порядок последовательно
для каждой редакции и блокирует параллельный запуск в том же workspace.
Не запускайте одновременно ручные сборки, меняющие встроенный агент.

Перед созданием архива упаковщик запускает `-edition` и `-version` у обоих
EXE, а также `-embedded-agent-edition` у сервера и `-build-version` у агента. Несовпадение редакций,
встроенного агента или версий останавливает упаковку. Флаги можно проверить
самостоятельно:

```powershell
./dist/events/netadmin.exe -edition
./dist/events/netadmin.exe -embedded-agent-edition
./dist/events/agent.exe -edition
./dist/events/netadmin.exe -version
./dist/events/agent.exe -version
./dist/events/agent.exe -build-version
```

Первые три команды должны вывести `events`. Сервер с `-version` и агент с
`-build-version` выводят одинаковую строку `NetAdmin Events 1.1.0` с ревизией
Git и возможной отметкой «с правками». Для обычной редакции это `standard`
и `NetAdmin 1.1.0`. Агент с `-version` выводит только `1.1.0`: этот формат
использует механизм самообновления.
Workflow релиза по тегу `v<версия>` выполняет проверки обеих редакций,
передаёт версию из тега helper и публикует оба ZIP вместе с их SHA-256.

Устанавливайте сервер и агенты одной редакции. Обычное самообновление агента
отклоняет файл другой редакции. Для перехода между редакциями требуется
переустановка из выбранного комплекта; порядок и подготовка описаны в
[инструкции Events](events.md). Events не имеет сертификата СЗИ и не заявляется
заменой сертифицированных средств защиты.
