package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"netadmin/internal/ingest"
)

// heartbeatSrv поднимает сервер только с эндпоинтом heartbeat.
func heartbeatSrv(t *testing.T, app *App) *httptest.Server {
	t.Helper()
	app.Ingest = ingest.New(app.DB, 90, 180, 365)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-heartbeat", app.AgentHeartbeat)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// rawPost шлёт запрос агента с полным контролем над заголовками и телом.
func rawPost(t *testing.T, srv *httptest.Server, path string, hdrs map[string]string, body []byte) (int, http.Header, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, out
}

func mac(key string, data []byte) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

// Токен устройства не должен приниматься как способ представиться: он только
// ключ подписи. Запрос, где вместо id устройства передан сам токен, отвергается.
func TestAgentTokenInHeaderRejected(t *testing.T) {
	app := newTestApp(t)
	srv := heartbeatSrv(t, app)
	const tok = "DEVTOK1"
	app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-1','online',?)", tok)

	body, _ := json.Marshal(map[string]any{
		"hostname": "WS-1", "timestamp": time.Now().UTC().Unix(), "nonce": testNonce(t),
	})
	// старый протокол: токен в заголовке
	code, _, _ := rawPost(t, srv, "/api/agent-heartbeat", map[string]string{
		"X-Agent-Token": tok,
		hdrSig:          mac(tok, body),
	}, body)
	if code != http.StatusUnauthorized {
		t.Fatalf("токен в заголовке должен отвергаться, получено %d", code)
	}
}

// Повторно проигранный запрос должен отбиваться по nonce, даже если подпись
// верна и timestamp ещё свежий.
func TestAgentReplayRejected(t *testing.T) {
	app := newTestApp(t)
	srv := heartbeatSrv(t, app)
	const tok = "DEVTOK2"
	res, _ := app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-2','online',?)", tok)
	id, _ := res.LastInsertId()

	body, _ := json.Marshal(map[string]any{
		"hostname": "WS-2", "cpu": 10.0,
		"timestamp": time.Now().UTC().Unix(), "nonce": testNonce(t),
	})
	hdrs := map[string]string{
		hdrDevice: strconv.FormatInt(id, 10),
		hdrSig:    mac(tok, body),
	}
	if code, _, _ := rawPost(t, srv, "/api/agent-heartbeat", hdrs, body); code != 200 {
		t.Fatalf("первый запрос должен пройти, получено %d", code)
	}
	code, _, _ := rawPost(t, srv, "/api/agent-heartbeat", hdrs, body)
	if code != http.StatusForbidden {
		t.Fatalf("повтор должен отвергаться, получено %d", code)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM events WHERE category='replay'").Scan(&n)
	if n == 0 {
		t.Fatal("повтор должен фиксироваться как событие безопасности")
	}
}

// Запрос со старым timestamp отвергается даже с корректной подписью и nonce.
func TestAgentStaleTimestampRejected(t *testing.T) {
	app := newTestApp(t)
	srv := heartbeatSrv(t, app)
	const tok = "DEVTOK3"
	res, _ := app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-3','online',?)", tok)
	id, _ := res.LastInsertId()

	body, _ := json.Marshal(map[string]any{
		"hostname":  "WS-3",
		"timestamp": time.Now().UTC().Add(-10 * time.Minute).Unix(),
		"nonce":     testNonce(t),
	})
	code, _, _ := rawPost(t, srv, "/api/agent-heartbeat", map[string]string{
		hdrDevice: strconv.FormatInt(id, 10),
		hdrSig:    mac(tok, body),
	}, body)
	if code != http.StatusForbidden {
		t.Fatalf("просроченный запрос должен отвергаться, получено %d", code)
	}
}

// Ответ сервера подписан ключом устройства — иначе подставной сервер мог бы
// навязать агенту задачу.
func TestAgentResponseIsSigned(t *testing.T) {
	app := newTestApp(t)
	srv := heartbeatSrv(t, app)
	const tok = "DEVTOK4"
	res, _ := app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-4','online',?)", tok)
	id, _ := res.LastInsertId()

	body, _ := json.Marshal(map[string]any{
		"hostname": "WS-4", "timestamp": time.Now().UTC().Unix(), "nonce": testNonce(t),
	})
	code, hdr, respBody := rawPost(t, srv, "/api/agent-heartbeat", map[string]string{
		hdrDevice: strconv.FormatInt(id, 10),
		hdrSig:    mac(tok, body),
	}, body)
	if code != 200 {
		t.Fatalf("ожидался 200, получено %d", code)
	}
	got := hdr.Get(hdrSig)
	if got == "" {
		t.Fatal("ответ сервера должен быть подписан")
	}
	if got != mac(tok, respBody) {
		t.Fatalf("подпись ответа не сходится: %s", got)
	}
}

// Enrollment выдаёт токен и id, но повторная регистрация устройства, у которого
// токен уже есть, запрещена: иначе по одному enrollment-токену можно было бы
// перехватить чужую машину, назвавшись её именем.
func TestEnrollmentIssuesTokenAndBlocksHijack(t *testing.T) {
	app := newTestApp(t)
	srv := heartbeatSrv(t, app)
	const enroll = "ENROLLTOK"
	writeEnrollToken(t, enroll)

	post := func() (int, []byte) {
		body, _ := json.Marshal(map[string]any{
			"hostname": "NEW-PC", "timestamp": time.Now().UTC().Unix(), "nonce": testNonce(t),
		})
		code, _, out := rawPost(t, srv, "/api/agent-heartbeat", map[string]string{
			hdrEnroll: "1",
			hdrSig:    mac(enroll, body),
		}, body)
		return code, out
	}

	code, out := post()
	if code != 200 {
		t.Fatalf("регистрация должна пройти, получено %d", code)
	}
	var r struct {
		Token    string `json:"token"`
		DeviceID int64  `json:"device_id"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if r.Token == "" || r.DeviceID == 0 {
		t.Fatalf("ожидались токен и device_id, получено %+v", r)
	}

	if code, _ = post(); code != http.StatusConflict {
		t.Fatalf("повторная регистрация занятого устройства должна отвергаться, получено %d", code)
	}
}

// Агент не может записать инвентарь от имени чужого хоста: устройство берётся
// из подписи, а не из поля hostname в теле.
func TestAgentCannotSpoofAnotherHost(t *testing.T) {
	app := newTestApp(t)
	app.Ingest = ingest.New(app.DB, 90, 180, 365)
	const tokA = "TOKA"
	resA, _ := app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('PC-A','online',?)", tokA)
	idA, _ := resA.LastInsertId()
	resB, _ := app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('PC-B','online','TOKB')")
	idB, _ := resB.LastInsertId()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-software", app.AgentSoftware)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// агент A подписывается своим ключом, но в теле называется PC-B
	body, _ := json.Marshal(map[string]any{
		"hostname":  "PC-B",
		"software":  []map[string]string{{"name": "Чужое ПО", "version": "1.0"}},
		"timestamp": time.Now().UTC().Unix(),
		"nonce":     testNonce(t),
	})
	code, _, _ := rawPost(t, srv, "/api/agent-software", map[string]string{
		hdrDevice: strconv.FormatInt(idA, 10),
		hdrSig:    mac(tokA, body),
	}, body)
	if code != 200 {
		t.Fatalf("ожидался 200, получено %d", code)
	}

	var nB int
	app.DB.QueryRow("SELECT COUNT(*) FROM software WHERE device_id=?", idB).Scan(&nB)
	if nB != 0 {
		t.Fatalf("инвентарь ушёл чужому устройству: %d записей у PC-B", nB)
	}
	var nA int
	app.DB.QueryRow("SELECT COUNT(*) FROM software WHERE device_id=?", idA).Scan(&nA)
	if nA != 1 {
		t.Fatalf("инвентарь должен записаться подписавшему устройству, у PC-A %d записей", nA)
	}
}

// Признак «на связи» должен обновляться на любом запросе агента, а не только
// на heartbeat: heartbeat адаптивный и при стабильной нагрузке приходит раз
// в 5 минут, из-за чего спокойные машины уезжали в offline.
func TestAnyAgentRequestMarksDeviceSeen(t *testing.T) {
	app := newTestApp(t)
	const tok = "SEENTOK"
	res, _ := app.DB.Exec(`INSERT INTO devices (hostname, status, agent_token, last_seen)
		VALUES ('WS-IDLE','offline',?,datetime('now','-10 minutes'))`, tok)
	id, _ := res.LastInsertId()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-tasks/poll", app.AgentTasksPoll)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// опрос очереди задач — запрос без единой метрики
	body, _ := json.Marshal(map[string]any{
		"hostname": "WS-IDLE", "timestamp": time.Now().UTC().Unix(), "nonce": testNonce(t),
	})
	code, _, _ := rawPost(t, srv, "/api/agent-tasks/poll", map[string]string{
		hdrDevice: strconv.FormatInt(id, 10),
		hdrSig:    mac(tok, body),
	}, body)
	if code != 200 {
		t.Fatalf("ожидался 200, получено %d", code)
	}

	var status string
	var fresh int
	app.DB.QueryRow(`SELECT status, last_seen > datetime('now','-1 minute') FROM devices WHERE id=?`, id).
		Scan(&status, &fresh)
	if status != "online" {
		t.Errorf("устройство должно вернуться в online, получено %q", status)
	}
	if fresh != 1 {
		t.Error("last_seen должен обновиться на любом запросе агента")
	}
}

// Агент вправе скачать только назначенный ему дистрибутив: иначе перебором
// идентификаторов выкачивался бы весь каталог ПО.
func TestAgentDownloadsOnlyAssignedPackage(t *testing.T) {
	app := newTestApp(t)
	const tok = "PKGTOK"
	res, _ := app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-P','online',?)", tok)
	id, _ := res.LastInsertId()

	dir := t.TempDir()
	t.Setenv("NETADMIN_DATA_DIR", dir)
	if err := os.MkdirAll(filepath.Join(dir, "packages"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, fn := range []string{"mine.bin", "other.bin"} {
		if err := os.WriteFile(filepath.Join(dir, "packages", fn), []byte("data"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	app.DB.Exec(`INSERT INTO packages (id, name, kind, filename, sha256) VALUES (1,'Своё','exe','mine.bin','aa')`)
	app.DB.Exec(`INSERT INTO packages (id, name, kind, filename, sha256) VALUES (2,'Чужое','exe','other.bin','bb')`)
	// назначен только первый
	app.DB.Exec(`INSERT INTO agent_tasks (device_id, kind, payload, label, status, package_id)
		VALUES (?, 'install', '{}', 'Установка', 'sent', 1)`, id)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/agent-package", app.AgentPackageDownload)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	get := func(pkgID string) int {
		q := url.Values{}
		q.Set("id", pkgID)
		q.Set("ts", strconv.FormatInt(time.Now().UTC().Unix(), 10))
		q.Set("nonce", testNonce(t))
		uri := "/api/agent-package?" + q.Encode()

		req, _ := http.NewRequest("GET", srv.URL+uri, nil)
		req.Header.Set(hdrDevice, strconv.FormatInt(id, 10))
		req.Header.Set(hdrSig, mac(tok, []byte("GET\n"+uri)))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code := get("1"); code != 200 {
		t.Errorf("назначенный дистрибутив должен отдаваться, получено %d", code)
	}
	if code := get("2"); code != http.StatusForbidden {
		t.Errorf("чужой дистрибутив должен отвергаться, получено %d", code)
	}
}
