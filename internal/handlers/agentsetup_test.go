package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"netadmin/internal/agentcfg"
	"netadmin/internal/config"
)

// Готовый установщик — это сборка агента с дописанным хвостом. Проверяем оба
// свойства: что отдан именно агент, а не что-то другое, и что настройки внутри
// те самые.

const fakeAgent = "MZ\x00\x00сборка агента для теста"

// adminSeq — номер для имени учётной записи: помощник вызывают и по два раза
// на тест, а логины в базе уникальны.
var adminSeq int

// getAsAdmin выполняет запрос от имени вошедшего администратора.
func getAsAdmin(t *testing.T, app *App, path string) *httptest.ResponseRecorder {
	t.Helper()
	adminSeq++
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = "192.168.1.10:1234"
	// Адрес, по которому открыта панель: именно он и уходит в установщик.
	// Явный выбор через ?host= здесь не проверить — он сверяется с реальными
	// интерфейсами машины (см. agentServerURL), а их в тесте не подменить.
	req.Host = "192.168.1.10:8765"
	req.AddCookie(sessionFor(t, app, "admin-setup-"+strconv.Itoa(adminSeq), "admin"))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	return rec
}

func TestAgentSetupExeCarriesSettings(t *testing.T) {
	app := newTestApp(t)
	withEmbeddedAgent(t, fakeAgent, "sha-ne-vazhen")
	writeEnrollToken(t, "postoyannyj-token")

	rec := getAsAdmin(t, app, "/settings/agent-setup.exe")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, ожидался 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.Bytes()
	if !bytes.HasPrefix(body, []byte(fakeAgent)) {
		t.Fatal("отдан не файл агента")
	}

	got, ok := agentcfg.Read(body)
	if !ok {
		t.Fatal("в отданном файле нет настроек — установщик не настроен")
	}
	if got.Token != "postoyannyj-token" {
		t.Errorf("вписан токен %q", got.Token)
	}
	if got.ServerURL != "http://192.168.1.10:8765" {
		t.Errorf("вписан адрес %q — не тот, по которому открыта панель", got.ServerURL)
	}
	// Файл собирается заново на каждую выдачу: кэшировать его нельзя.
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q — браузер может отдать чужой файл из кэша", cc)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, ".exe") {
		t.Errorf("Content-Disposition %q — файл не предложат сохранить как .exe", cd)
	}
}

// Установщик с одноразовым кодом внутри: код тот же, что показан строкой
// рядом, — иначе файл и команда открывали бы разные двери.
func TestEnrollCodeInstallerCarriesCode(t *testing.T) {
	app := newTestApp(t)
	withEmbeddedAgent(t, fakeAgent, "sha-ne-vazhen")

	res, err := app.DB.Exec(`INSERT INTO enroll_codes (code, expires_at, max_uses)
		VALUES ('odnorazovyj-kod', datetime('now','+1 hour'), 5)`)
	if err != nil {
		t.Fatalf("завести код: %v", err)
	}
	id, _ := res.LastInsertId()

	rec := getAsAdmin(t, app, enrollInstallerPath(id))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, ожидался 200: %s", rec.Code, rec.Body.String())
	}
	got, ok := agentcfg.Read(rec.Body.Bytes())
	if !ok {
		t.Fatal("в отданном файле нет настроек")
	}
	if got.Token != "odnorazovyj-kod" {
		t.Errorf("вписан токен %q вместо кода", got.Token)
	}
}

// Отозванный или истёкший код файла не даёт: иначе отзыв кода ничего не менял
// бы для тех, кто успел открыть страницу.
func TestEnrollCodeInstallerRejectsDeadCode(t *testing.T) {
	cases := map[string]string{
		"отозван":            `INSERT INTO enroll_codes (code, expires_at, max_uses, revoked) VALUES ('k', datetime('now','+1 hour'), 5, 1)`,
		"истёк":              `INSERT INTO enroll_codes (code, expires_at, max_uses) VALUES ('k', datetime('now','-1 hour'), 5)`,
		"исчерпан установок": `INSERT INTO enroll_codes (code, expires_at, max_uses, used_count) VALUES ('k', datetime('now','+1 hour'), 5, 5)`,
	}
	for name, ins := range cases {
		t.Run(name, func(t *testing.T) {
			app := newTestApp(t)
			withEmbeddedAgent(t, fakeAgent, "sha-ne-vazhen")
			res, err := app.DB.Exec(ins)
			if err != nil {
				t.Fatalf("завести код: %v", err)
			}
			id, _ := res.LastInsertId()

			rec := getAsAdmin(t, app, enrollInstallerPath(id))
			if rec.Code == http.StatusOK {
				t.Error("файл отдан по недействующему коду")
			}
		})
	}
}

// Сервер без встроенного агента должен сказать об этом, а не отдать пустой файл
// с настройками внутри.
func TestAgentSetupExeWithoutAgentBuild(t *testing.T) {
	app := newTestApp(t)
	withoutEmbeddedAgent(t)
	writeEnrollToken(t, "token")

	rec := getAsAdmin(t, app, "/settings/agent-setup.exe")
	if rec.Code == http.StatusOK {
		t.Fatalf("отдано %d байт при отсутствующей сборке агента", rec.Body.Len())
	}
}

// Без токена отдавать нечего: файл без ключа не зарегистрирует машину, и
// человек узнал бы об этом только на месте.
func TestAgentSetupExeWithoutToken(t *testing.T) {
	app := newTestApp(t)
	withEmbeddedAgent(t, fakeAgent, "sha-ne-vazhen")
	cfg := config.Load()
	cfg.AgentToken = ""
	if err := config.Save(cfg); err != nil {
		t.Fatalf("сохранить настройки: %v", err)
	}

	rec := getAsAdmin(t, app, "/settings/agent-setup.exe")
	if rec.Code == http.StatusOK {
		t.Error("файл отдан без токена регистрации")
	}
}

func enrollInstallerPath(id int64) string {
	return "/settings/enroll-code/" + strconv.FormatInt(id, 10) + "/installer"
}

// Страница ждёт первого подключения по этому счётчику: она запоминает его при
// загрузке и сравнивает с ним ответы опроса.
func TestEnrolledAgentsCountsAndNamesLast(t *testing.T) {
	app := newTestApp(t)

	rec := getAsAdmin(t, app, "/api/agents/enrolled")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d", rec.Code)
	}
	var empty enrolledAgents
	if err := json.Unmarshal(rec.Body.Bytes(), &empty); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	if empty.Count != 0 || empty.Last != nil {
		t.Errorf("на пустой базе: %+v", empty)
	}

	if _, err := app.DB.Exec(`INSERT INTO devices (hostname, agent_token) VALUES
		('WS-1','t1'), ('WS-2','t2')`); err != nil {
		t.Fatalf("завести устройства: %v", err)
	}
	// без агента — не считается: страница ждёт именно подключившегося агента
	if _, err := app.DB.Exec(`INSERT INTO devices (hostname) VALUES ('PRINTER-1')`); err != nil {
		t.Fatalf("завести устройство: %v", err)
	}

	var got enrolledAgents
	if err := json.Unmarshal(getAsAdmin(t, app, "/api/agents/enrolled").Body.Bytes(), &got); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	if got.Count != 2 {
		t.Errorf("насчитано %d машин с агентом, ожидалось 2", got.Count)
	}
	if got.Last == nil || got.Last.Hostname != "WS-2" {
		t.Errorf("последней названа %+v, ожидалась WS-2", got.Last)
	}
}

// Счётчик виден только администратору: страница установки агентов — его.
func TestEnrolledAgentsRefusesViewer(t *testing.T) {
	app := newTestApp(t)
	req := httptest.NewRequest("GET", "/api/agents/enrolled", nil)
	req.RemoteAddr = "192.168.1.10:1234"
	req.AddCookie(sessionFor(t, app, "smotritel", "viewer"))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Error("роль viewer получила счётчик агентов")
	}
}

// Первый шаг мастера отмечается пройденным по машине сервера, а не по факту
// нажатия кнопки: нажать могли и неудачно.
func TestLocalAgentInstalledLooksAtServerHost(t *testing.T) {
	app := newTestApp(t)
	if app.localAgentInstalled() {
		t.Fatal("агент на этой машине засчитан на пустой базе")
	}

	host, err := os.Hostname()
	if err != nil || host == "" {
		t.Skip("имя машины недоступно")
	}
	if _, err := app.DB.Exec(
		`INSERT INTO devices (hostname, agent_token) VALUES (?, 'tok')`, host); err != nil {
		t.Fatalf("завести устройство: %v", err)
	}
	if !app.localAgentInstalled() {
		t.Errorf("агент на машине сервера (%s) не засчитан", host)
	}
}

// Чужая машина с агентом первый шаг не закрывает.
func TestLocalAgentInstalledIgnoresOtherHosts(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.DB.Exec(
		`INSERT INTO devices (hostname, agent_token) VALUES ('CHUZHAYA-MASHINA','tok')`); err != nil {
		t.Fatalf("завести устройство: %v", err)
	}
	if app.localAgentInstalled() {
		t.Error("агент на чужой машине засчитан за установку на этой")
	}
}
