package monitor

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	if res := Check("http", srv.URL); !res.Up {
		t.Fatalf("http проверка должна быть up: %+v", res)
	}
	// TCP по адресу того же листенера
	addr := strings.TrimPrefix(srv.URL, "http://")
	if res := Check("tcp", addr); !res.Up {
		t.Fatalf("tcp до живого листенера должен быть up: %+v", res)
	}
}

func TestCheckDown(t *testing.T) {
	if res := Check("tcp", "127.0.0.1:1"); res.Up {
		t.Fatal("tcp на закрытый порт 1 должен быть down")
	}
	if res := Check("http", "http://127.0.0.1:1"); res.Up {
		t.Fatal("http на закрытый порт должен быть down")
	}
}

func TestCheckDNS(t *testing.T) {
	if res := Check("dns", "localhost"); !res.Up {
		t.Fatalf("dns localhost должен резолвиться: %+v", res)
	}
	if res := Check("dns", "no-such-host.invalid"); res.Up {
		t.Fatal("несуществующий домен должен быть down")
	}
}

func Test5xxIsDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	if res := Check("http", srv.URL); res.Up {
		t.Fatal("HTTP 503 должен считаться недоступным")
	}
}
