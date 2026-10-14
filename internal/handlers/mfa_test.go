package handlers

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"netadmin/internal/auth"
)

func mfaRequest(a *App, method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", "mfa-test-csrf")
	r := httptest.NewRequest(method, "https://127.0.0.1"+path, strings.NewReader(form.Encode()))
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "mfa-test-csrf"})
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	w := httptest.NewRecorder()
	a.Routes().ServeHTTP(w, r)
	return w
}

func responseCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}

// Independent authenticator input for the full HTTP provisioning flow.
func authenticatorCode(t *testing.T, secret string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var step [8]byte
	binary.BigEndian.PutUint64(step[:], uint64(time.Now().Unix()/30))
	h := hmac.New(sha1.New, key)
	h.Write(step[:])
	mac := h.Sum(nil)
	offset := int(mac[len(mac)-1] & 15)
	value := binary.BigEndian.Uint32(mac[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

func httpEnableMFA(t *testing.T, a *App, cookie *http.Cookie, name string) (*http.Cookie, []string) {
	t.Helper()
	var id int64
	a.DB.QueryRow("SELECT id FROM users WHERE username=?", name).Scan(&id)
	w := mfaRequest(a, "POST", "/profile/mfa/begin", url.Values{"password": {"Parol12345"}}, cookie)
	if w.Code != 303 {
		t.Fatalf("begin: %d %s", w.Code, w.Body.String())
	}
	state, err := a.mfa().Status(id, cookie.Value)
	if err != nil || state.SetupSecret == "" {
		t.Fatalf("draft: %+v %v", state, err)
	}
	w = mfaRequest(a, "POST", "/profile/mfa/enable", url.Values{"code": {authenticatorCode(t, state.SetupSecret)}}, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Резервные коды созданы") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	renewed := responseCookie(w, "session")
	if renewed == nil || renewed.Value == cookie.Value || !renewed.Secure || !renewed.HttpOnly {
		t.Fatal("session not renewed securely")
	}
	// Plaintext recovery codes exist only in this confirmation response.
	var codes []string
	body := w.Body.String()
	for _, piece := range strings.Split(body, "<code>")[1:] {
		value := strings.SplitN(piece, "</code>", 2)[0]
		if len(value) == 35 {
			codes = append(codes, value)
		}
	}
	if len(codes) != 10 {
		t.Fatalf("recovery code count: %d", len(codes))
	}
	if strings.Contains(body, state.SetupSecret) {
		t.Fatal("enabled profile exposed authenticator seed")
	}
	return renewed, codes
}

func TestMFAHTTPProvisioningLoginAndRecovery(t *testing.T) {
	loginLimiter, userLockout, mfaActionsLimiter = newRateLimiter(), newRateLimiter(), newRateLimiter()
	a := newTestApp(t)
	original := sessionFor(t, a, "mfa-http", "admin")
	active, codes := httpEnableMFA(t, a, original, "mfa-http")
	w := mfaRequest(a, "GET", "/profile", nil, original)
	if w.Code != 302 {
		t.Fatal("old session retained access after MFA activation")
	}
	w = mfaRequest(a, "GET", "/profile", nil, active)
	if w.Code != 200 || strings.Contains(w.Body.String(), codes[0]) {
		t.Fatal("recovery codes shown again on profile GET")
	}
	w = mfaRequest(a, "POST", "/login", url.Values{"username": {"mfa-http"}, "password": {"Parol12345"}})
	if w.Code != 303 || w.Header().Get("Location") != "/login/mfa" || responseCookie(w, "session") != nil {
		t.Fatal("password alone authenticated MFA user")
	}
	pending := responseCookie(w, mfaCookie)
	if pending == nil || !pending.Secure || !pending.HttpOnly || pending.Path != "/login" {
		t.Fatal("unsafe challenge cookie")
	}
	w = mfaRequest(a, "GET", "/profile", nil, pending)
	if w.Code != 302 {
		t.Fatal("MFA challenge usable as application session")
	}
	w = mfaRequest(a, "POST", "/login/mfa", url.Values{"code": {"invalid"}}, pending)
	if w.Code != 200 || responseCookie(w, "session") != nil {
		t.Fatal("invalid factor authenticated")
	}
	w = mfaRequest(a, "POST", "/login/mfa", url.Values{"code": {codes[0]}}, pending)
	loggedIn := responseCookie(w, "session")
	if w.Code != 303 || loggedIn == nil || !loggedIn.Secure {
		t.Fatalf("recovery login: %d %s", w.Code, w.Body.String())
	}
	w = mfaRequest(a, "POST", "/login/mfa", url.Values{"code": {codes[0]}}, pending)
	if responseCookie(w, "session") != nil {
		t.Fatal("completed challenge issued another session")
	}
	w = mfaRequest(a, "POST", "/profile/mfa/disable", url.Values{"password": {"Parol12345"}, "code": {codes[1]}}, loggedIn)
	if w.Code != 303 || responseCookie(w, "session") == nil {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	var id int64
	a.DB.QueryRow("SELECT id FROM users WHERE username='mfa-http'").Scan(&id)
	if enabled, err := a.mfa().Enabled(id); err != nil || enabled {
		t.Fatal("factor still enabled")
	}
	rows, err := a.DB.Query("SELECT detail FROM audit_log")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var detail string
		rows.Scan(&detail)
		for _, code := range codes {
			if strings.Contains(detail, code) {
				t.Fatal("recovery code leaked to audit")
			}
		}
	}
}

func TestMFATransportCSRFAndDemo(t *testing.T) {
	cases := []struct {
		url, peer string
		tls       bool
		want      bool
	}{
		{"http://127.0.0.1/profile", "127.0.0.1:123", false, true},
		{"http://localhost/profile", "127.0.0.1:123", false, true},
		{"http://[::1]/profile", "[::1]:123", false, true},
		{"http://127.0.0.1/profile", "192.168.1.15:123", false, false},
		{"http://server.local/profile", "127.0.0.1:123", false, false},
		{"http://server.local/profile", "192.168.1.15:123", false, false},
		{"https://server.local/profile", "192.168.1.15:123", true, true},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", c.url, nil)
		r.RemoteAddr = c.peer
		r.Header.Set("X-Forwarded-Proto", "https")
		if c.tls {
			r.TLS = &tls.ConnectionState{}
		}
		if got := mfaTransportAllowed(r); got != c.want {
			t.Fatalf("transport %s/%s: %t", c.url, c.peer, got)
		}
	}
	a := newTestApp(t)
	cookie := sessionFor(t, a, "mfa-security", "viewer")
	for _, kind := range []string{"csrf", "lan", "demo"} {
		r := httptest.NewRequest("POST", "https://127.0.0.1/profile/mfa/begin", strings.NewReader("password=Parol12345&csrf_token=ok"))
		r.RemoteAddr = "127.0.0.1:40000"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookie)
		r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "ok"})
		if kind == "csrf" {
			r.Header.Set("X-CSRF-Token", "wrong")
		}
		if kind == "lan" {
			r.TLS = nil
			r.Host = "server.local"
			r.RemoteAddr = "192.168.1.20:40000"
		}
		a.Demo = kind == "demo"
		w := httptest.NewRecorder()
		a.Routes().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("%s accepted setup: %d", kind, w.Code)
		}
		if _, err := os.Stat(a.mfa().KeyPath); !os.IsNotExist(err) {
			t.Fatal("rejected operation created key")
		}
	}
}

func TestAnalystCannotRunAdministrativeOrDeviceActions(t *testing.T) {
	a := newTestApp(t)
	analyst := sessionFor(t, a, "access-analyst", "analyst")
	for _, route := range routesFromSource(t) {
		if route.method != "POST" || isAgentRoute(route.pattern) {
			continue
		}
		if _, ok := publicPost[route.pattern]; ok {
			continue
		}
		w := mfaRequest(a, "POST", requestPath(route.pattern), nil, analyst)
		if w.Code != 403 && !(w.Code == 302 && strings.HasPrefix(w.Header().Get("Location"), "/login")) {
			t.Errorf("analyst accepted %s: %d", route.pattern, w.Code)
		}
	}
	if (&auth.User{Role: "analyst"}).CanWrite() || (&auth.User{Role: "analyst"}).IsAdmin() {
		t.Fatal("analyst received operator/admin authority")
	}
}
