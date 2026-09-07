package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"netadmin/internal/ingest"
)

// makeCode заводит код напрямую в базе: так тест задаёт срок и лимит точно,
// не подстраиваясь под значения формы.
func makeCode(t *testing.T, a *App, code string, ttl time.Duration, maxUses, used int, revoked bool) {
	t.Helper()
	exp := time.Now().UTC().Add(ttl).Format(codeTimeLay)
	rev := 0
	if revoked {
		rev = 1
	}
	if _, err := a.DB.Exec(`INSERT INTO enroll_codes (code, expires_at, max_uses, used_count, revoked)
		VALUES (?,?,?,?,?)`, code, exp, maxUses, used, rev); err != nil {
		t.Fatalf("вставка кода: %v", err)
	}
}

// TestActiveEnrollKeysFiltersUnusable — код перестаёт подходить, когда кончился
// срок, кончились установки или его отозвали. Ошибка здесь означала бы, что
// «одноразовый» код работает и дальше — то есть фича не работает вовсе.
func TestActiveEnrollKeysFiltersUnusable(t *testing.T) {
	a := newTestApp(t)

	makeCode(t, a, "живой", time.Hour, 5, 2, false)
	makeCode(t, a, "без-лимита", time.Hour, 0, 100, false)
	makeCode(t, a, "истёкший", -time.Minute, 5, 0, false)
	makeCode(t, a, "исчерпанный", time.Hour, 2, 2, false)
	makeCode(t, a, "отозванный", time.Hour, 5, 0, true)

	got := map[string]bool{}
	for _, k := range a.activeEnrollKeys() {
		got[k] = true
	}
	for _, want := range []string{"живой", "без-лимита"} {
		if !got[want] {
			t.Errorf("код %q должен действовать", want)
		}
	}
	for _, bad := range []string{"истёкший", "исчерпанный", "отозванный"} {
		if got[bad] {
			t.Errorf("код %q не должен подходить для регистрации", bad)
		}
	}
}

// TestEnrollWithCodeAndItsExhaustion — сквозная проверка: устройство
// регистрируется по коду, установка списывается, и код с лимитом 1 больше
// никого не пускает.
func TestEnrollWithCodeAndItsExhaustion(t *testing.T) {
	a := newTestApp(t)
	a.Ingest = ingest.New(a.DB, 90, 180, 365) // heartbeat пишет метрики
	writeEnrollToken(t, "постоянный-токен")
	makeCode(t, a, "разовый", time.Hour, 1, 0, false)

	srv := httptest.NewServer(a.Routes())
	defer srv.Close()

	code, _ := agentPost(t, a, srv, "/api/agent-heartbeat", "разовый",
		map[string]any{"hostname": "PC-CODE", "os": "Windows"})
	if code != http.StatusOK {
		t.Fatalf("регистрация по коду вернула %d", code)
	}

	var used int
	if err := a.DB.QueryRow("SELECT used_count FROM enroll_codes WHERE code='разовый'").Scan(&used); err != nil {
		t.Fatalf("чтение счётчика: %v", err)
	}
	if used != 1 {
		t.Errorf("списано установок: %d, ожидалась 1", used)
	}
	if keys := a.activeEnrollKeys(); len(keys) != 0 {
		t.Errorf("исчерпанный код всё ещё действует: %v", keys)
	}

	// вторая машина тем же кодом уже не проходит
	code, _ = agentPost(t, a, srv, "/api/agent-heartbeat", "разовый",
		map[string]any{"hostname": "PC-SECOND", "os": "Windows"})
	if code == http.StatusOK {
		t.Error("исчерпанный код зарегистрировал вторую машину")
	}
}

// TestPermanentTokenStillWorks — постоянный токен остаётся рабочим: им
// пользуются install_agent.bat и скрипты раскатки.
func TestPermanentTokenStillWorks(t *testing.T) {
	a := newTestApp(t)
	a.Ingest = ingest.New(a.DB, 90, 180, 365) // heartbeat пишет метрики
	writeEnrollToken(t, "постоянный-токен")
	makeCode(t, a, "разовый", time.Hour, 1, 0, false)

	srv := httptest.NewServer(a.Routes())
	defer srv.Close()

	code, _ := agentPost(t, a, srv, "/api/agent-heartbeat", "постоянный-токен",
		map[string]any{"hostname": "PC-PERM", "os": "Windows"})
	if code != http.StatusOK {
		t.Fatalf("регистрация постоянным токеном вернула %d", code)
	}

	// постоянный токен не должен расходовать чужие коды
	var used int
	a.DB.QueryRow("SELECT used_count FROM enroll_codes WHERE code='разовый'").Scan(&used)
	if used != 0 {
		t.Errorf("постоянный токен списал установку с кода: used=%d", used)
	}
}

// TestUnknownKeyRejected — посторонний ключ не должен подходить ни при каких
// действующих кодах: проверка перебирает несколько ключей, и ошибка в ней
// открыла бы регистрацию любому.
func TestUnknownKeyRejected(t *testing.T) {
	a := newTestApp(t)
	writeEnrollToken(t, "постоянный-токен")
	makeCode(t, a, "разовый", time.Hour, 5, 0, false)

	srv := httptest.NewServer(a.Routes())
	defer srv.Close()

	code, _ := agentPost(t, a, srv, "/api/agent-heartbeat", "чужой-ключ",
		map[string]any{"hostname": "PC-EVIL", "os": "Windows"})
	if code == http.StatusOK {
		t.Fatal("посторонний ключ зарегистрировал устройство")
	}
}

// TestCreateEnrollCodeLimits — форма не должна позволять превратить код во
// второй постоянный токен.
func TestCreateEnrollCodeLimits(t *testing.T) {
	a := newTestApp(t)
	admin := sessionFor(t, a, "admin", "admin")

	form := url.Values{"minutes": {"100000"}, "uses": {"100000"}}
	r := httptest.NewRequest("POST", "/settings/enroll-code", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(admin)
	rec := httptest.NewRecorder()

	a.CreateEnrollCode(rec, r)

	var maxUses int
	var expires string
	if err := a.DB.QueryRow(
		"SELECT max_uses, expires_at FROM enroll_codes ORDER BY id DESC LIMIT 1").
		Scan(&maxUses, &expires); err != nil {
		t.Fatalf("код не создан: %v", err)
	}
	if maxUses > maxCodeUses {
		t.Errorf("число установок %d выше предела %d", maxUses, maxCodeUses)
	}
	exp, err := time.Parse(codeTimeLay, expires)
	if err != nil {
		t.Fatalf("срок не разобран: %v", err)
	}
	if d := time.Until(exp.UTC()); d > maxCodeTTL+time.Minute {
		t.Errorf("срок %v выше предела %v", d, maxCodeTTL)
	}
}

// TestRevokeEnrollCode — отзыв действует немедленно.
func TestRevokeEnrollCode(t *testing.T) {
	a := newTestApp(t)
	admin := sessionFor(t, a, "admin", "admin")
	makeCode(t, a, "разовый", time.Hour, 5, 0, false)

	var id int64
	if err := a.DB.QueryRow("SELECT id FROM enroll_codes WHERE code='разовый'").Scan(&id); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/settings/enroll-code/"+strconv.FormatInt(id, 10)+"/revoke", nil)
	r.SetPathValue("id", strconv.FormatInt(id, 10))
	r.AddCookie(admin)
	rec := httptest.NewRecorder()

	a.RevokeEnrollCode(rec, r)

	if keys := a.activeEnrollKeys(); len(keys) != 0 {
		t.Errorf("отозванный код всё ещё действует: %v", keys)
	}
}

// TestEnrollCodesRequireAdmin — коды пускают новые устройства в систему.
func TestEnrollCodesRequireAdmin(t *testing.T) {
	a := newTestApp(t)
	viewer := sessionFor(t, a, "viewer", "viewer")

	for _, tc := range []struct {
		path string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"/settings/enroll-code", a.CreateEnrollCode},
		{"/settings/enroll-code/1/revoke", a.RevokeEnrollCode},
	} {
		r := httptest.NewRequest("POST", tc.path, nil)
		r.AddCookie(viewer)
		rec := httptest.NewRecorder()
		tc.fn(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: viewer получил %d, ожидался 403", tc.path, rec.Code)
		}
	}
}

// TestPurgeEnrollCodesKeepsRecent — уборка не должна сносить то, что ещё
// пригодится для разбора в журнале.
func TestPurgeEnrollCodesKeepsRecent(t *testing.T) {
	a := newTestApp(t)
	makeCode(t, a, "вчерашний", -24*time.Hour, 1, 1, false)
	makeCode(t, a, "древний", -30*24*time.Hour, 1, 1, false)

	PurgeEnrollCodes(a.DB)

	var n int
	a.DB.QueryRow("SELECT COUNT(*) FROM enroll_codes WHERE code='вчерашний'").Scan(&n)
	if n != 1 {
		t.Error("недавно истёкший код удалён слишком рано")
	}
	a.DB.QueryRow("SELECT COUNT(*) FROM enroll_codes WHERE code='древний'").Scan(&n)
	if n != 0 {
		t.Error("давно истёкший код не убран")
	}
}

// TestReenrollWithCodeIssuesNewToken — переустановка агента на машине, которая
// уже числится в инвентаре.
//
// Пока сервер отвечал на это 409, агент так и не получал персонального токена и
// продолжал подписываться кодом регистрации. Работало это ровно до истечения
// кода: потом машина уходила в оффлайн, хотя агент был установлен и запущен.
func TestReenrollWithCodeIssuesNewToken(t *testing.T) {
	a := newTestApp(t)
	a.Ingest = ingest.New(a.DB, 90, 180, 365)
	writeEnrollToken(t, "постоянный-токен")
	makeCode(t, a, "первый", time.Hour, 5, 0, false)

	srv := httptest.NewServer(a.Routes())
	defer srv.Close()

	// первая установка
	code, body := agentPost(t, a, srv, "/api/agent-heartbeat", "первый",
		map[string]any{"hostname": "PC-RE", "os": "Windows"})
	if code != http.StatusOK {
		t.Fatalf("первая регистрация вернула %d", code)
	}
	first := tokenFromResponse(t, body)

	// переустановка новым кодом: состояния у агента больше нет
	makeCode(t, a, "второй", time.Hour, 5, 0, false)
	code, body = agentPost(t, a, srv, "/api/agent-heartbeat", "второй",
		map[string]any{"hostname": "PC-RE", "os": "Windows"})
	if code != http.StatusOK {
		t.Fatalf("повторная регистрация по коду вернула %d — агент останется без токена", code)
	}
	second := tokenFromResponse(t, body)
	if second == "" || second == first {
		t.Error("новый персональный токен не выдан")
	}

	var stored string
	a.DB.QueryRow("SELECT agent_token FROM devices WHERE hostname='PC-RE'").Scan(&stored)
	if stored != second {
		t.Error("в базе остался прежний токен устройства")
	}
	if n := countRows(a, "SELECT COUNT(*) FROM devices WHERE hostname='PC-RE'"); n != 1 {
		t.Errorf("устройств с этим именем: %d, ожидалось одно", n)
	}
}

// TestReenrollWithPermanentTokenStillRefused — постоянным токеном владеет любой,
// кто когда-либо ставил агента. Разрешить ему перевыпуск значило бы отдать
// чужое устройство тому, кто назовётся его именем.
func TestReenrollWithPermanentTokenStillRefused(t *testing.T) {
	a := newTestApp(t)
	a.Ingest = ingest.New(a.DB, 90, 180, 365)
	writeEnrollToken(t, "постоянный-токен")
	makeCode(t, a, "код", time.Hour, 5, 0, false)

	srv := httptest.NewServer(a.Routes())
	defer srv.Close()

	if code, _ := agentPost(t, a, srv, "/api/agent-heartbeat", "код",
		map[string]any{"hostname": "PC-PERM2", "os": "Windows"}); code != http.StatusOK {
		t.Fatalf("первая регистрация вернула %d", code)
	}
	code, _ := agentPost(t, a, srv, "/api/agent-heartbeat", "постоянный-токен",
		map[string]any{"hostname": "PC-PERM2", "os": "Windows"})
	if code != http.StatusConflict {
		t.Errorf("постоянным токеном перерегистрация вернула %d, ожидался 409", code)
	}
}

// tokenFromResponse достаёт выданный токен устройства из ответа heartbeat.
func tokenFromResponse(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("ответ сервера: %v", err)
	}
	return resp.Token
}
