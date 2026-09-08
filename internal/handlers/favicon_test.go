package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Значок вкладки браузер просит сам и до входа: на странице входа, на портале
// заявок, при добавлении в закладки. Если маршрут окажется за сессией или
// файл выпадет из встроенной статики, вкладка молча останется пустой — ошибки
// человек не увидит нигде.
func TestFaviconServedWithoutSession(t *testing.T) {
	app := newTestApp(t)
	srv := app.Routes()

	for _, path := range []string{"/favicon.ico", "/static/favicon.svg"} {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "192.168.1.10:1234" // запрос из локальной сети
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s: код %d, ожидался 200", path, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/") {
			t.Errorf("%s: Content-Type %q — браузер не примет это за картинку", path, ct)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("%s: пустой ответ", path)
		}
	}
}

// Тот же значок, что лежит в статике, должен отдаваться и по корневому пути:
// один файл, два адреса, разойтись им негде.
func TestFaviconRootMatchesStatic(t *testing.T) {
	app := newTestApp(t)
	srv := app.Routes()

	get := func(path string) []byte {
		t.Helper()
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "192.168.1.10:1234"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: код %d", path, rec.Code)
		}
		return rec.Body.Bytes()
	}

	root, static := get("/favicon.ico"), get("/static/favicon.ico")
	if !bytes.Equal(root, static) {
		t.Errorf("/favicon.ico и /static/favicon.ico отдают разное (%d и %d Б)",
			len(root), len(static))
	}
	if !bytes.HasPrefix(root, []byte{0x00, 0x00, 0x01, 0x00}) {
		t.Error("/favicon.ico отдаёт не .ico: не совпала сигнатура")
	}
}
