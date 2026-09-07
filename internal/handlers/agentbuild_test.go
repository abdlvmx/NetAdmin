package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withEmbeddedAgent подставляет встроенную сборку агента: в тестовом окружении
// её нет — файл появляется только при сборке релиза.
func withEmbeddedAgent(t *testing.T, content, sha string) {
	t.Helper()
	prev := agentEmbedded
	agentEmbedded = func() ([]byte, string, bool) { return []byte(content), sha, true }
	t.Cleanup(func() { agentEmbedded = prev })
}

// withoutEmbeddedAgent убирает встроенную сборку на время теста.
//
// Нужна потому, что встроенная сборка появляется в бинарнике только когда
// перед сборкой положили agent.exe в internal/agentbin/bin. Тесты, у которых
// premise «сборки нет», иначе проходили бы на чистом клоне и падали на машине
// разработчика и в CI релиза — то есть ровно там, где важны.
func withoutEmbeddedAgent(t *testing.T) {
	t.Helper()
	prev := agentEmbedded
	agentEmbedded = func() ([]byte, string, bool) { return nil, "", false }
	t.Cleanup(func() { agentEmbedded = prev })
}

// TestEmbeddedAgentServedWithoutUpload — то, ради чего агент и встроен: сервер
// отдаёт сборку сам, ничего загружать в «Установку ПО» не нужно.
func TestEmbeddedAgentServedWithoutUpload(t *testing.T) {
	app := newTestApp(t)
	withEmbeddedAgent(t, "встроенная сборка", "embeddedsha")

	b, ok := app.latestAgentBuild()
	if !ok {
		t.Fatal("встроенная сборка не найдена")
	}
	if !b.Embedded || b.SHA256 != "embeddedsha" {
		t.Errorf("получено %+v, ожидалась встроенная сборка", b)
	}

	srv := httptest.NewServer(app.Routes())
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/agent.exe")
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/agent.exe вернул %d", resp.StatusCode)
	}
	if body := readAll(t, resp); body != "встроенная сборка" {
		t.Errorf("отдано %q", body)
	}
}

// TestUploadedAgentWinsOverEmbedded — загруженная сборка важнее встроенной:
// иначе после обновления парка новые машины получали бы старую версию
// из серверного бинарника.
func TestUploadedAgentWinsOverEmbedded(t *testing.T) {
	app := newTestApp(t)
	withEmbeddedAgent(t, "встроенная сборка", "embeddedsha")
	addAgentBuild(t, app, "agent.exe", "загруженная сборка", "uploadedsha")

	b, ok := app.latestAgentBuild()
	if !ok {
		t.Fatal("сборка агента не найдена")
	}
	if b.Embedded || b.SHA256 != "uploadedsha" {
		t.Errorf("получено %+v, ожидалась загруженная сборка", b)
	}

	srv := httptest.NewServer(app.Routes())
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/agent.exe")
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()
	if body := readAll(t, resp); body != "загруженная сборка" {
		t.Errorf("отдано %q, ожидалась загруженная сборка", body)
	}
}

// TestEnrollScriptUsesEmbeddedChecksum — скрипт сверяет контрольную сумму
// скачанного файла, поэтому она должна быть от той сборки, которая и отдаётся.
func TestEnrollScriptUsesEmbeddedChecksum(t *testing.T) {
	app := newTestApp(t)
	withEmbeddedAgent(t, "встроенная сборка", "embeddedsha")

	srv := httptest.NewServer(app.Routes())
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/enroll.ps1")
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer resp.Body.Close()
	if script := readAll(t, resp); !strings.Contains(script, "embeddedsha") {
		t.Errorf("в скрипте нет суммы встроенной сборки:\n%s", script)
	}
}

// TestInstallLocalAgentUsesLoopback — агенту на машине сервера адрес нужен
// через петлю: смена IP интерфейса не должна разрывать связь с самим собой.
func TestInstallLocalAgentUsesLoopback(t *testing.T) {
	app := newTestApp(t)
	admin := sessionFor(t, app, "admin", "admin")

	var gotURL, gotToken string
	app.InstallAgent = func(serverURL, token string) (string, error) {
		gotURL, gotToken = serverURL, token
		return "установлено", nil
	}

	r := httptest.NewRequest("POST", "/settings/agent-install-local", nil)
	r.Host = "192.168.1.64:8765"
	r.AddCookie(admin)
	rec := httptest.NewRecorder()

	app.InstallLocalAgent(rec, r)

	if strings.Contains(location(rec), "error=") {
		t.Fatalf("установка отклонена: %s", location(rec))
	}
	if gotURL != "http://127.0.0.1:8765" {
		t.Errorf("агенту передан адрес %q, ожидался http://127.0.0.1:8765", gotURL)
	}
	if gotToken == "" {
		t.Error("агенту не передан токен")
	}
}

// TestInstallLocalAgentUnavailable — сервер без встроенного агента должен
// объяснить, почему кнопка не работает, а не молчать.
func TestInstallLocalAgentUnavailable(t *testing.T) {
	app := newTestApp(t)
	admin := sessionFor(t, app, "admin", "admin")

	r := httptest.NewRequest("POST", "/settings/agent-install-local", nil)
	r.AddCookie(admin)
	rec := httptest.NewRecorder()

	app.InstallLocalAgent(rec, r) // InstallAgent не задан

	if !strings.Contains(location(rec), "error=") {
		t.Errorf("недоступность установки не объяснена: %s", location(rec))
	}
}

// TestInstallLocalAgentRequiresAdmin — установка агента меняет систему.
func TestInstallLocalAgentRequiresAdmin(t *testing.T) {
	app := newTestApp(t)
	viewer := sessionFor(t, app, "viewer", "viewer")
	app.InstallAgent = func(string, string) (string, error) { return "", nil }

	r := httptest.NewRequest("POST", "/settings/agent-install-local", nil)
	r.AddCookie(viewer)
	rec := httptest.NewRecorder()

	app.InstallLocalAgent(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer получил %d, ожидался 403", rec.Code)
	}
}
