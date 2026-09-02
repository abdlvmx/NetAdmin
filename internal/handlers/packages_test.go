package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

func TestKindByExt(t *testing.T) {
	cases := map[string]string{
		"7zip.msi": "msi", "setup.EXE": "exe", "deploy.ps1": "script",
		"run.bat": "script", "x.cmd": "script", "noext": "exe",
	}
	for name, want := range cases {
		if got := kindByExt(name); got != want {
			t.Errorf("kindByExt(%q)=%q, ожидалось %q", name, got, want)
		}
	}
}

func TestPackagesPageRenders(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "packages", packagesData{
		User: &auth.User{ID: 1, Username: "admin", Role: "admin"}, Active: "packages",
		Packages: []pkgRow{{ID: 1, Name: "7-Zip", Original: "7z.msi", Kind: "msi", SizeMB: "1.5 МБ", Created: "01.01 10:00"}},
		Devices:  []employeeOpt{{ID: 1, Name: "WS-1"}},
		Recent:   []deployRow{{Device: "WS-1", Package: "Установка: 7-Zip", Status: "done", Result: "ok", Created: "01.01 10:05"}},
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	if !strings.Contains(body, "Загрузить дистрибутив") {
		t.Fatal("в выводе нет формы загрузки")
	}
}

// Страница должна показывать раздел обновления агента и сводку версий парка.
func TestPackagesPageShowsAgentUpdate(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "packages", packagesData{
		User: &auth.User{ID: 1, Username: "admin", Role: "admin"}, Active: "packages",
		Packages: []pkgRow{
			{ID: 1, Name: "NetAdmin agent 1.1.0", Kind: "exe", SizeMB: "9.3 МБ"},
			{ID: 2, Name: "7-Zip", Kind: "msi", SizeMB: "1.5 МБ"},
		},
		AgentVersions: []verRow{{Version: "1.1.0", Count: 12}, {Version: "неизвестна", Count: 3}},
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	if !strings.Contains(body, "Обновление агента") {
		t.Fatal("нет раздела обновления агента")
	}
	if !strings.Contains(body, "1.1.0 — 12") {
		t.Fatal("нет сводки версий агента")
	}
	// в списке сборок агента предлагаются только .exe
	if !strings.Contains(body, "NetAdmin agent 1.1.0 (9.3 МБ)") {
		t.Fatal("сборка .exe не предложена")
	}
	if strings.Contains(body, "7-Zip (1.5 МБ)") {
		t.Fatal(".msi не должен предлагаться как сборка агента")
	}
}

// adminReq — запрос от имени администратора с действующей сессией.
func adminReq(t *testing.T, app *App, method, path, body string) *http.Request {
	t.Helper()
	var id int64
	if app.DB.QueryRow("SELECT id FROM users WHERE username='root'").Scan(&id) != nil {
		hash, err := auth.HashPassword("Parol12345")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		res, err := app.DB.Exec("INSERT INTO users (username, role, password_hash) VALUES ('root','admin',?)", hash)
		if err != nil {
			t.Fatalf("user: %v", err)
		}
		id, _ = res.LastInsertId()
	}
	tok, err := auth.CreateSession(app.DB, id)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "session", Value: tok})
	return req
}

// Обновлением агента может быть только .exe с контрольной суммой: иначе задача
// уехала бы на весь парк и там не выполнилась.
func TestDeployAgentUpdateRejectsUnsuitablePackage(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec(`INSERT INTO packages (id, name, kind, filename, sha256) VALUES (1,'7-Zip','msi','x.msi','abc')`)
	app.DB.Exec(`INSERT INTO packages (id, name, kind, filename, sha256) VALUES (2,'agent','exe','y.exe','')`)
	app.DB.Exec(`INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-1','online','TOK')`)

	for _, tc := range []struct{ name, pkg, want string }{
		{"не .exe", "1", "должна быть .exe"},
		{"без контрольной суммы", "2", "контрольной суммы"},
	} {
		rec := httptest.NewRecorder()
		app.DeployAgentUpdate(rec, adminReq(t, app, "POST", "/packages/agent-update", "package_id="+tc.pkg))
		loc, _ := url.QueryUnescape(rec.Header().Get("Location"))
		if !strings.Contains(loc, tc.want) {
			t.Errorf("%s: ожидалась ошибка со словами %q, получено %q", tc.name, tc.want, loc)
		}
	}

	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM agent_tasks WHERE kind='selfupdate'").Scan(&n)
	if n != 0 {
		t.Fatalf("задачи обновления не должны ставиться, поставлено %d", n)
	}
}

// Годная сборка ставится в очередь всем машинам с агентом.
func TestDeployAgentUpdateEnqueuesForAllAgents(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec(`INSERT INTO packages (id, name, kind, filename, sha256)
		VALUES (1,'NetAdmin agent 1.1.0','exe','a.exe','deadbeef')`)
	app.DB.Exec(`INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-1','online','T1')`)
	app.DB.Exec(`INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-2','online','T2')`)
	app.DB.Exec(`INSERT INTO devices (hostname, status) VALUES ('no-agent','online')`)

	rec := httptest.NewRecorder()
	app.DeployAgentUpdate(rec, adminReq(t, app, "POST", "/packages/agent-update", "package_id=1"))

	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM agent_tasks WHERE kind='selfupdate'").Scan(&n)
	if n != 2 {
		t.Fatalf("ожидалось 2 задачи (только машины с агентом), поставлено %d", n)
	}
	var payload string
	app.DB.QueryRow("SELECT payload FROM agent_tasks WHERE kind='selfupdate' LIMIT 1").Scan(&payload)
	if !strings.Contains(payload, "deadbeef") {
		t.Fatalf("в задаче должна быть контрольная сумма сборки, получено %s", payload)
	}
}
