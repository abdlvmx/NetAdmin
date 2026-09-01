package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"netadmin/internal/config"
	"netadmin/internal/db"
)

// newTestApp поднимает App с реальной схемой во временном файле БД.
//
// Каталог создаётся вручную (не t.TempDir): на Windows авто-очистка t.TempDir()
// падает с «directory is not empty», если фоновые notify-горутины или WAL-файлы
// SQLite ещё держат файлы в момент удаления — это помечает прошедший тест как
// FAIL. Здесь чистим сами, игнорируя такие гонки.
func newTestApp(t *testing.T) *App {
	t.Helper()
	dir, err := os.MkdirTemp("", "natest")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Setenv("NETADMIN_DATA_DIR", dir) // notify/config не лезут в реальный config.json
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.InitSchema(d); err != nil {
		t.Fatalf("schema: %v", err)
	}
	t.Cleanup(func() {
		d.Close()
		_ = os.RemoveAll(dir) // ошибку игнорируем (фоновые горутины могли держать файл)
	})
	return &App{DB: d}
}

// writeEnrollToken кладёт enrollment-токен в config.json тестового каталога данных.
func writeEnrollToken(t *testing.T, token string) {
	t.Helper()
	cfg := config.Load()
	cfg.AgentToken = token
	if err := config.Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
}

func testNonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return hex.EncodeToString(b)
}

// agentPost выполняет подписанный запрос агента по текущему протоколу: токен по
// сети не идёт, в заголовке — id устройства, а токен служит ключом HMAC. Если
// устройство с таким токеном ещё не заведено, запрос уходит как enrollment.
// Возвращает статус и тело ответа.
func agentPost(t *testing.T, app *App, srv *httptest.Server, path, token string, payload map[string]any) (int, []byte) {
	t.Helper()
	payload["timestamp"] = time.Now().UTC().Unix()
	if _, ok := payload["nonce"]; !ok {
		payload["nonce"] = testNonce(t)
	}
	b, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	var id int64
	if app.DB.QueryRow("SELECT id FROM devices WHERE agent_token=?", token).Scan(&id) == nil && id > 0 {
		req.Header.Set(hdrDevice, strconv.FormatInt(id, 10))
	} else {
		req.Header.Set(hdrEnroll, "1")
	}
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write(b)
	req.Header.Set(hdrSig, hex.EncodeToString(mac.Sum(nil)))

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// postJSON — короткая форма agentPost, когда нужен только код ответа.
func postJSON(t *testing.T, app *App, srv *httptest.Server, path, token string, payload map[string]any) int {
	t.Helper()
	code, _ := agentPost(t, app, srv, path, token, payload)
	return code
}
