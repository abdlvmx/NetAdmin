package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/web"
)

// adminRequest выполняет запрос от имени администратора.
func adminRequest(t *testing.T, a *App, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	hash, _ := auth.HashPassword("Parol12345")
	var id int64
	if err := a.DB.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&id); err != nil {
		res, err := a.DB.Exec(`INSERT INTO users (username, full_name, role, password_hash, is_active)
			VALUES ('admin','Админ','admin',?,1)`, hash)
		if err != nil {
			t.Fatalf("создание админа: %v", err)
		}
		id, _ = res.LastInsertId()
	}
	tok, err := auth.CreateSession(a.DB, id)
	if err != nil {
		t.Fatalf("сессия: %v", err)
	}
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "127.0.0.1:40000"
	req.AddCookie(&http.Cookie{Name: "session", Value: tok})
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)
	return rec
}

// Скачанный установщик не должен требовать ручной правки: адрес и токен уже в нём.
func TestAgentInstallerFillsPlaceholders(t *testing.T) {
	a := newTestApp(t)
	cfg := config.Load()
	cfg.AgentToken = "TESTTOKEN1234567890"
	if err := config.Save(cfg); err != nil {
		t.Fatalf("сохранение конфига: %v", err)
	}

	rec := adminRequest(t, a, "GET", "http://192.168.1.64:8765/settings/agent-installer")
	if rec.Code != http.StatusOK {
		t.Fatalf("получен код %d, тело: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// заглушек не должно остаться ни одной — иначе установщик молча поставит
	// агента, который никуда не подключится
	for _, ph := range []string{"YOUR_URL_HERE", "YOUR_TOKEN_HERE"} {
		if strings.Contains(body, ph) {
			t.Errorf("в установщике осталась заглушка %s", ph)
		}
	}
	if !strings.Contains(body, `set "SERVER_URL=http://192.168.1.64:8765"`) {
		t.Error("не подставлен адрес сервера")
	}
	if !strings.Contains(body, `set "ENROLL_TOKEN=TESTTOKEN1234567890"`) {
		t.Error("не подставлен токен")
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "install_agent.bat") {
		t.Errorf("файл должен скачиваться, а не открываться: %q", cd)
	}
	// cmd.exe требует CRLF
	if strings.Contains(strings.ReplaceAll(body, "\r\n", ""), "\n") {
		t.Error("в .bat остались переводы строк без возврата каретки")
	}
}

// Адрес берётся из того, по которому открыт интерфейс, но локальный заменяется
// на сетевой: иначе каждый агент искал бы сервер на своей же машине.
func TestAgentInstallerAvoidsLocalhost(t *testing.T) {
	a := newTestApp(t)
	cfg := config.Load()
	cfg.AgentToken = "TESTTOKEN1234567890"
	_ = config.Save(cfg)

	rec := adminRequest(t, a, "GET", "http://127.0.0.1:8765/settings/agent-installer")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "SERVER_URL=http://127.0.0.1") {
		t.Error("в установщик попал адрес обратной петли — агенты по нему не найдут сервер")
	}
}

// Установщик содержит enrollment-токен, поэтому доступен только администратору.
func TestAgentInstallerRequiresAdmin(t *testing.T) {
	a := newTestApp(t)
	hash, _ := auth.HashPassword("Parol12345")
	res, err := a.DB.Exec(`INSERT INTO users (username, full_name, role, password_hash, is_active)
		VALUES ('viewer','Наблюдатель','viewer',?,1)`, hash)
	if err != nil {
		t.Fatalf("создание viewer: %v", err)
	}
	id, _ := res.LastInsertId()
	tok, _ := auth.CreateSession(a.DB, id)

	req := httptest.NewRequest("GET", "http://192.168.1.64:8765/settings/agent-installer", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	req.AddCookie(&http.Cookie{Name: "session", Value: tok})
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer получил %d вместо 403", rec.Code)
	}
}

// Встроенный шаблон — копия deploy/install_agent.bat. Если их правят порознь,
// ручная и скачиваемая установка со временем разойдутся.
func TestEmbeddedInstallerMatchesDeploy(t *testing.T) {
	embedded, err := web.AgentInstaller()
	if err != nil {
		t.Fatalf("встроенный шаблон недоступен: %v", err)
	}
	onDisk, err := os.ReadFile("../../deploy/install_agent.bat")
	if err != nil {
		t.Skipf("deploy/install_agent.bat не найден: %v", err)
	}
	norm := func(b []byte) string {
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}
	if norm(embedded) != norm(onDisk) {
		t.Error("internal/web/assets/install_agent.bat разошёлся с deploy/install_agent.bat — " +
			"скопируйте актуальную версию")
	}
}

// Администратор может выбрать адрес сам — но только из тех, что есть на машине:
// иначе в установщик попал бы произвольный адрес из ссылки.
func TestAgentInstallerAcceptsOnlyLocalAddresses(t *testing.T) {
	a := newTestApp(t)
	cfg := config.Load()
	cfg.AgentToken = "TESTTOKEN1234567890"
	_ = config.Save(cfg)

	// чужой адрес игнорируется — берётся тот, по которому открыт интерфейс
	rec := adminRequest(t, a, "GET",
		"http://192.168.1.64:8765/settings/agent-installer?host=203.0.113.7")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "203.0.113.7") {
		t.Error("в установщик попал адрес, которого нет на этой машине")
	}
	if !strings.Contains(rec.Body.String(), `set "SERVER_URL=http://192.168.1.64:8765"`) {
		t.Error("должен был остаться адрес, по которому открыт интерфейс")
	}

	// а свой — принимается
	local := localIPv4s()
	if len(local) == 0 {
		t.Skip("на этой машине нет частных IPv4")
	}
	rec = adminRequest(t, a, "GET",
		"http://192.168.1.64:8765/settings/agent-installer?host="+local[0].IP)
	if !strings.Contains(rec.Body.String(), `set "SERVER_URL=http://`+local[0].IP+`:8765"`) {
		t.Errorf("выбранный адрес %s не подставлен", local[0].IP)
	}
}

// Страница настроек показывает адреса для выбора и путь к установщику.
//
// Проверка идёт по адресам ссылок, а не по подписям кнопок: подписи меняются
// вместе с текстом страницы, а сломанный маршрут — это неработающая установка.
func TestSettingsShowsServerAddresses(t *testing.T) {
	a := newTestApp(t)
	rec := adminRequest(t, a, "GET", "http://192.168.1.64:8765/settings")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/settings/agent-installer") {
		t.Error("на странице нет ссылки на установщик .bat")
	}
	for _, addr := range localIPv4s() {
		if !strings.Contains(body, addr.IP) {
			t.Errorf("адрес %s (%s) не предложен для выбора", addr.IP, addr.Iface)
		}
	}
}

// Со встроенной сборкой агента страница предлагает и готовый файл — самый
// короткий путь установки, ради которого весь порядок шагов и переставлялся.
func TestSettingsOffersReadyInstaller(t *testing.T) {
	a := newTestApp(t)
	withEmbeddedAgent(t, "MZ agent", "sha")
	writeEnrollToken(t, "token")

	rec := adminRequest(t, a, "GET", "http://192.168.1.64:8765/settings")
	body := rec.Body.String()
	if !strings.Contains(body, "/settings/agent-setup.exe") {
		t.Error("нет ссылки на готовый агент с постоянным токеном")
	}
	if !strings.Contains(body, `data-act="copy"`) {
		t.Error("команду установки нельзя скопировать одной кнопкой")
	}
}
