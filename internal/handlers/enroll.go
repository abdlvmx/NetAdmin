package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netadmin/internal/agentbin"
)

// Установка агента одной командой.
//
// Прежний путь требовал принести на машину два файла (agent.exe и скачанный
// install_agent.bat) и запустить второй от администратора. Здесь сервер отдаёт
// и сборку агента, и скрипт установки, а администратору достаточно вставить в
// консоль одну строку со страницы «Настройки».
//
// Оба маршрута открыты без сессии намеренно: команда выполняется на чужой
// машине, где никакой сессии нет. Секрета в них тоже нет — enrollment-токен
// администратор подставляет сам, копируя строку со страницы за логином. Доступ
// и без того ограничен разрешёнными подсетями (см. withSecurity).

// agentBuild — сборка агента, которую сервер отдаёт для установки.
//
// Источников два: сборка, встроенная в сам сервер, и более новая, загруженная
// администратором в «Установку ПО» для обновления парка. Загруженная важнее —
// иначе после обновления парка новые машины продолжали бы получать старую
// версию из бинарника.
type agentBuild struct {
	Stored   string // имя файла в каталоге packages; пусто у встроенной сборки
	SHA256   string
	Size     int64
	Embedded bool
}

// latestAgentBuild возвращает сборку агента для установки.
func (a *App) latestAgentBuild() (agentBuild, bool) {
	var b agentBuild
	err := a.DB.QueryRow(`SELECT COALESCE(filename,''), COALESCE(sha256,''), COALESCE(size,0)
		FROM packages WHERE LOWER(COALESCE(original_name,''))='agent.exe'
		ORDER BY id DESC LIMIT 1`).Scan(&b.Stored, &b.SHA256, &b.Size)
	// Файл мог пропасть с диска, а строка в packages остаться: после
	// восстановления базы из копии это штатный случай — копия снимается с
	// базы, а каталог packages в неё не входит. Раньше /agent.exe отвечал
	// «этот сервер собран без встроенного агента», хотя агент как раз внутри,
	// и установка одной командой переставала работать без всякой причины.
	if err == nil && b.Stored != "" && b.SHA256 != "" {
		if _, err := os.Stat(filepath.Join(packagesDir(), b.Stored)); err == nil {
			return b, true
		}
	}
	if data, sum, ok := agentEmbedded(); ok {
		return agentBuild{SHA256: sum, Size: int64(len(data)), Embedded: true}, true
	}
	return agentBuild{}, false
}

// agentEmbedded — источник встроенной сборки агента. Вынесен переменной, чтобы
// тесты могли подставить сборку: в тестовом окружении её нет (файл появляется
// только при сборке релиза), а порядок «загруженная важнее встроенной» —
// логика, от которой зависит, какую версию получат новые машины.
var agentEmbedded = agentbin.Bytes

// agentBuildMatch — сверка встроенной сборки агента с самим сервером. Вынесена
// переменной по той же причине, что и agentEmbedded: в тестовом окружении
// встроенной сборки нет, а от результата сверки зависит, предупредит ли
// страница настроек о собранном не в том порядке сервере.
var agentBuildMatch = agentbin.Compare

// AgentBinary — GET /agent.exe : сборка агента для установки.
func (a *App) AgentBinary(w http.ResponseWriter, r *http.Request) {
	b, ok := a.latestAgentBuild()
	if !ok {
		http.Error(w, "сборка агента недоступна: этот сервер собран без встроенного агента — "+
			"загрузите agent.exe в разделе «Установка ПО»", http.StatusNotFound)
		return
	}

	// Скрипт установки просит ровно ту сборку, о которой ему сказали. Если на
	// сервере уже другая — это не подмена, а обычное обновление парка, и
	// говорить о нём надо соответственно: прежде сумма и файл брались двумя
	// запросами, и загрузка новой сборки между ними роняла идущие установки
	// словами «файл повреждён или подменён» — штатное обновление выглядело
	// как атака.
	if want := r.URL.Query().Get("sha256"); want != "" && !strings.EqualFold(want, b.SHA256) {
		http.Error(w, "сборка агента на сервере обновилась, пока шла установка: "+
			"откройте «Настройки» и выполните команду установки заново", http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="agent.exe"`)

	if b.Embedded {
		data, _, _ := agentEmbedded()
		// Время сборки самого сервера: встроенный файл меняется только вместе
		// с ним, и по нему клиент правильно решает вопрос кэширования.
		http.ServeContent(w, r, "agent.exe", serverBuildTime(), bytes.NewReader(data))
		return
	}

	path := filepath.Join(packagesDir(), b.Stored)
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "файл сборки агента недоступен", http.StatusNotFound)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, "agent.exe", modTime(path), f)
}

// serverBuildTime — время файла самого сервера. Служит меткой версии для
// встроенной сборки агента: отдельного времени у неё нет.
func serverBuildTime() time.Time {
	exe, err := os.Executable()
	if err != nil {
		return time.Time{}
	}
	return modTime(exe)
}

// modTime — время файла для http.ServeContent: по нему браузер и PowerShell
// решают вопрос кэширования.
func modTime(path string) time.Time {
	if st, err := os.Stat(path); err == nil {
		return st.ModTime()
	}
	return time.Time{}
}

// EnrollScript — GET /enroll.ps1 : скрипт установки агента.
//
// Скрипт рассчитан на запуск через `irm … | iex`, поэтому директива #requires
// в нём бесполезна (она действует только для файлов) — права проверяются явно.
func (a *App) EnrollScript(w http.ResponseWriter, r *http.Request) {
	server := agentServerURL(r)
	b, ok := a.latestAgentBuild()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !ok {
		// PowerShell выполнит это как скрипт и покажет внятную причину —
		// иначе человек увидел бы только пустой ответ.
		fmt.Fprint(w, "throw 'На сервере NetAdmin не загружена сборка агента. "+
			"Откройте раздел «Установка ПО» и загрузите файл agent.exe.'\n")
		return
	}

	fmt.Fprint(w, enrollScript(server, b.SHA256))
}

// enrollScript собирает текст скрипта. Вынесено отдельной функцией, чтобы тест
// мог проверить подстановки, не поднимая HTTP.
func enrollScript(server, sha string) string {
	var s strings.Builder
	s.WriteString("$ErrorActionPreference = 'Stop'\n")
	s.WriteString("$srv = '" + psQuote(server) + "'\n")
	s.WriteString("$sha = '" + psQuote(sha) + "'\n")
	s.WriteString(`
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Запустите PowerShell от имени администратора и повторите команду.'
}
if (-not $t) {
  throw 'Не задан токен. Скопируйте команду целиком со страницы «Настройки» сервера NetAdmin.'
}

$tmp = Join-Path $env:TEMP 'netadmin-agent-setup.exe'
Write-Host 'Загрузка агента...'
try {
  Invoke-WebRequest -Uri "$srv/agent.exe?sha256=$sha" -OutFile $tmp -UseBasicParsing
} catch {
  $code = 0
  try { $code = [int]$_.Exception.Response.StatusCode } catch {}
  if ($code -eq 409) {
    throw 'Сборка агента на сервере обновилась, пока шла установка. Откройте «Настройки» и выполните команду заново.'
  }
  throw "Не удалось загрузить агента с $srv : $($_.Exception.Message)"
}

$got = (Get-FileHash $tmp -Algorithm SHA256).Hash
if ($got -ne $sha) {
  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  throw "Контрольная сумма не совпала: файл повреждён при загрузке или подменён. Повторите команду."
}

& $tmp -install "-server=$srv" "-token=$t"
$code = $LASTEXITCODE
Remove-Item $tmp -Force -ErrorAction SilentlyContinue
if ($code -ne 0) { throw "Установка агента завершилась с кодом $code." }
`)
	return s.String()
}

// psQuote экранирует одинарные кавычки для строкового литерала PowerShell.
// Значения приходят из адреса запроса и из базы, и незакрытая кавычка не должна
// превращаться в исполняемый код на чужой машине.
func psQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// enrollCommand — готовая строка для вставки в консоль на устанавливаемой
// машине. Показывается на странице «Настройки».
func enrollCommand(server, token string) string {
	return fmt.Sprintf(`powershell -c "$t='%s'; irm %s/enroll.ps1 | iex"`, token, server)
}
