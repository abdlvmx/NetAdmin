package handlers

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"netadmin/internal/config"
)

func TestHTTPSCookiesAreSecureAndHTTPRemainsUsable(t *testing.T) {
	for _, secure := range []bool{false, true} {
		r := httptest.NewRequest("GET", "http://panel.example.test/", nil)
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		setSessionCookie(w, "secret", r)
		ensureCSRF(w, r)
		cookies := w.Result().Cookies()
		if len(cookies) != 2 {
			t.Fatalf("cookies: %+v", cookies)
		}
		for _, c := range cookies {
			if c.Secure != secure {
				t.Errorf("%s secure=%t want %t", c.Name, c.Secure, secure)
			}
		}
		w = httptest.NewRecorder()
		clearSessionCookie(w, r)
		if c := w.Result().Cookies()[0]; c.Secure != secure || c.MaxAge != -1 {
			t.Fatalf("logout cookie: %+v", c)
		}
	}
}

func TestHTTPSAgentAddressKeepsConfiguredCertificateName(t *testing.T) {
	t.Setenv("NETADMIN_DATA_DIR", t.TempDir())
	cfg := config.Load()
	cfg.TLSCertFile, cfg.TLSKeyFile, cfg.PublicURL = "server.crt", "server.key", "https://panel.example.test:8765"
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://192.168.1.20:8765/settings", nil)
	if got := agentServerURL(r); got != cfg.PublicURL {
		t.Fatalf("agent URL changed certificate name: %q", got)
	}
	if got := localServerURL(r); got != cfg.PublicURL {
		t.Fatalf("local installer URL: %q", got)
	}
}
