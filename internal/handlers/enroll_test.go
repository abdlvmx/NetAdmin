package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("чтение ответа: %v", err)
	}
	return string(b)
}

func getStatus(t *testing.T, srv *httptest.Server, path string) int {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		t.Fatalf("запрос %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// addAgentBuild кладёт «сборку агента» в каталог дистрибутивов и заводит запись
// в packages — как это делает загрузка файла на странице «Установка ПО».
func addAgentBuild(t *testing.T, a *App, original, content, sha string) {
	t.Helper()
	stored := randToken() + ".exe"
	if err := os.WriteFile(filepath.Join(packagesDir(), stored), []byte(content), 0o600); err != nil {
		t.Fatalf("запись дистрибутива: %v", err)
	}
	if _, err := a.DB.Exec(`INSERT INTO packages (name, filename, original_name, kind, size, sha256)
		VALUES (?,?,?,'exe',?,?)`, original, stored, original, len(content), sha); err != nil {
		t.Fatalf("вставка пакета: %v", err)
	}
}

// TestLatestAgentBuildPicksNewestAgentExe — сборка для установки берётся из
// «Установки ПО» по имени файла. Проверяем обе стороны отбора: посторонние
// дистрибутивы не годятся, а из нескольких agent.exe берётся последний.
func TestLatestAgentBuildPicksNewestAgentExe(t *testing.T) {
	a := newTestApp(t)
	withoutEmbeddedAgent(t) // проверяется отбор среди загруженных

	if _, ok := a.latestAgentBuild(); ok {
		t.Fatal("на пустой базе сборка агента найдена")
	}

	addAgentBuild(t, a, "7zip.exe", "не агент", "aaa")
	if _, ok := a.latestAgentBuild(); ok {
		t.Error("посторонний дистрибутив принят за сборку агента")
	}

	addAgentBuild(t, a, "agent.exe", "старый", "bbb")
	addAgentBuild(t, a, "AGENT.EXE", "новый", "ccc")

	b, ok := a.latestAgentBuild()
	if !ok {
		t.Fatal("загруженная сборка агента не найдена")
	}
	if b.SHA256 != "ccc" {
		t.Errorf("взята сборка с sha %q, ожидалась последняя загруженная (ccc)", b.SHA256)
	}
}

// TestEnrollScriptWithoutBuild — команда установки не должна молча ничего не
// делать: без загруженной сборки скрипт обязан сказать, чего не хватает.
func TestEnrollScriptWithoutBuild(t *testing.T) {
	a := newTestApp(t)
	withoutEmbeddedAgent(t)
	srv := httptest.NewServer(a.Routes())
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/enroll.ps1")
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()
	body := readAll(t, resp)

	if !strings.Contains(body, "throw") || !strings.Contains(body, "Установка ПО") {
		t.Errorf("скрипт без сборки агента не объясняет причину:\n%s", body)
	}

	code := getStatus(t, srv, "/agent.exe")
	if code != http.StatusNotFound {
		t.Errorf("/agent.exe без загруженной сборки вернул %d, ожидался 404", code)
	}
}

// TestEnrollScriptContent — в скрипте должны быть адрес сервера, контрольная
// сумма и проверка прав: без любой из трёх частей установка либо не пройдёт,
// либо пройдёт не тем файлом.
func TestEnrollScriptContent(t *testing.T) {
	a := newTestApp(t)
	withoutEmbeddedAgent(t)
	addAgentBuild(t, a, "agent.exe", "сборка", "d3adbeef")

	srv := httptest.NewServer(a.Routes())
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/enroll.ps1")
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()
	script := readAll(t, resp)

	for _, want := range []string{"d3adbeef", "Get-FileHash", "IsInRole", "-install", "$t"} {
		if !strings.Contains(script, want) {
			t.Errorf("в скрипте нет %q:\n%s", want, script)
		}
	}
}

// TestAgentBinaryServesUpload — по /agent.exe должен отдаваться именно
// загруженный файл: иначе проверка контрольной суммы в скрипте не сойдётся.
func TestAgentBinaryServesUpload(t *testing.T) {
	a := newTestApp(t)
	withoutEmbeddedAgent(t)
	addAgentBuild(t, a, "agent.exe", "содержимое сборки", "abc123")

	srv := httptest.NewServer(a.Routes())
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/agent.exe")
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()
	if body := readAll(t, resp); body != "содержимое сборки" {
		t.Errorf("отдано %q, ожидалось содержимое загруженной сборки", body)
	}
}

// TestEnrollScriptQuotesValues — адрес попадает в строковый литерал PowerShell,
// и кавычка в нём не должна разрывать литерал: иначе на чужой машине
// выполнилось бы что-то помимо установки.
func TestEnrollScriptQuotesValues(t *testing.T) {
	s := enrollScript("http://host'; rm -rf /; '", "sha")
	if strings.Contains(s, "$srv = 'http://host'; rm") {
		t.Errorf("кавычка в адресе разорвала литерал:\n%s", s)
	}
	if !strings.Contains(s, "''") {
		t.Error("одинарная кавычка не экранирована удвоением")
	}
}

// TestEnrollCommand — строка, которую администратор копирует со страницы
// «Настройки»: токен подставляется на его стороне, а не в скрипте.
func TestEnrollCommand(t *testing.T) {
	cmd := enrollCommand("http://192.168.1.10:8765", "TOKEN123")
	for _, want := range []string{"TOKEN123", "http://192.168.1.10:8765/enroll.ps1", "iex"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("в команде нет %q: %s", want, cmd)
		}
	}
}
