package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Пропавший с диска файл загруженной сборки не должен отменять установку.
//
// После восстановления базы из копии это штатный случай: копия снимается с
// базы, а каталог packages в неё не входит — строка о загруженной сборке
// возвращается, файла рядом нет. Раньше /agent.exe отвечал 404 со словами
// «этот сервер собран без встроенного агента», хотя агент как раз внутри.
func TestMissingUploadFallsBackToEmbeddedAgent(t *testing.T) {
	app := newTestApp(t)
	withEmbeddedAgent(t, "встроенная сборка", "embeddedsha")
	addAgentBuild(t, app, "agent.exe", "загруженная сборка", "uploadedsha")

	// файл дистрибутива пропал, строка в packages осталась
	var stored string
	if err := app.DB.QueryRow("SELECT filename FROM packages ORDER BY id DESC LIMIT 1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(packagesDir(), stored)); err != nil {
		t.Fatal(err)
	}

	b, ok := app.latestAgentBuild()
	if !ok {
		t.Fatal("сборка агента не найдена, хотя встроенная на месте")
	}
	if !b.Embedded {
		t.Errorf("выбрана %+v, ожидался откат на встроенную сборку", b)
	}

	srv := httptest.NewServer(app.Routes())
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/agent.exe")
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/agent.exe вернул %d, ожидалась встроенная сборка", resp.StatusCode)
	}
	if body := readAll(t, resp); body != "встроенная сборка" {
		t.Errorf("отдано %q", body)
	}
}

// Обновление сборки посреди установки — не подмена, и говорить о нём надо
// иначе.
//
// Скрипт получает контрольную сумму одним запросом, а файл — другим. Загрузка
// новой сборки между ними роняла идущие установки словами «файл повреждён или
// подменён»: штатное обновление парка выглядело как атака. Теперь скрипт
// просит ровно ту сборку, о которой ему сказали.
func TestAgentBinaryTellsThatBuildChanged(t *testing.T) {
	app := newTestApp(t)
	withEmbeddedAgent(t, "встроенная сборка", "embeddedsha")

	srv := httptest.NewServer(app.Routes())
	defer srv.Close()

	// та сборка, о которой знает скрипт, — отдаётся
	resp, err := srv.Client().Get(srv.URL + "/agent.exe?sha256=embeddedsha")
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("запрошенная сборка не отдана: %d", resp.StatusCode)
	}

	// другая — отказ, по которому видно, что произошло
	stale, err := srv.Client().Get(srv.URL + "/agent.exe?sha256=предыдущаясборка")
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer stale.Body.Close()
	if stale.StatusCode != http.StatusConflict {
		t.Fatalf("устаревшая сборка отдана с кодом %d, ожидался 409", stale.StatusCode)
	}
	if body := readAll(t, stale); !strings.Contains(body, "обновилась") {
		t.Errorf("в отказе не сказано, что сборка обновилась: %q", body)
	}
}

// Скрипт установки должен просить именно ту сборку, сумму которой он проверяет.
func TestEnrollScriptAsksForTheBuildItKnows(t *testing.T) {
	s := enrollScript("http://192.168.1.10:8765", "abc123")
	if !strings.Contains(s, "/agent.exe?sha256=$sha") {
		t.Errorf("скрипт скачивает сборку не по её сумме:\n%s", s)
	}
	if !strings.Contains(s, "409") {
		t.Error("скрипт не объясняет обновление сборки: отказ 409 остаётся без перевода на человеческий")
	}
}
