package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testWelcomeHandler() *welcomeHandler {
	return &welcomeHandler{host: "127.0.0.1:19234", path: "/welcome/random/", token: "current-secret",
		canInstall: true, canAgent: true, result: make(chan welcomeResult, 1)}
}
func welcomePost(h *welcomeHandler, values url.Values, host, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://"+host+h.path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
func TestWelcomePageHasRolesAndProtectedForms(t *testing.T) {
	h := testWelcomeHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+h.host+h.path, nil))
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	for _, label := range []string{"Посмотреть демо", "Настроить сервер", "Подключить этот компьютер", "name=\"token\"", "Windows запросит права администратора"} {
		if !strings.Contains(rec.Body.String(), label) {
			t.Errorf("missing %q", label)
		}
	}
	if h.chosen || len(h.result) != 0 {
		t.Fatal("viewing the page chose an action")
	}
	if rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("welcome page protections missing")
	}
}
func TestWelcomeRejectsExternalAndStaleRequests(t *testing.T) {
	for _, tc := range []struct{ name, host, origin, token string }{
		{"rebound host", "attacker.example:19234", "http://attacker.example:19234", "current-secret"},
		{"external origin", "127.0.0.1:19234", "https://attacker.example", "current-secret"},
		{"missing token", "127.0.0.1:19234", "", ""},
		{"stale token", "127.0.0.1:19234", "http://127.0.0.1:19234", "previous-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testWelcomeHandler()
			rec := welcomePost(h, url.Values{"action": {"install"}, "lan": {"yes"}, "token": {tc.token}}, tc.host, tc.origin)
			if rec.Code != http.StatusForbidden || h.chosen || len(h.result) != 0 {
				t.Fatalf("unsafe request: status=%d chosen=%v", rec.Code, h.chosen)
			}
		})
	}
}
func TestWelcomeInstallationUsesExplicitFirewallChoice(t *testing.T) {
	for _, tc := range []struct {
		lan  string
		want firewallChoice
	}{{"", firewallNo}, {"yes", firewallYes}} {
		h := testWelcomeHandler()
		rec := welcomePost(h, url.Values{"action": {"install"}, "lan": {tc.lan}, "token": {h.token}}, h.host, "http://"+h.host)
		if rec.Code != http.StatusOK {
			t.Fatal(rec.Code)
		}
		result := <-h.result
		if result.Choice != choiceInstall || result.Firewall != tc.want {
			t.Fatalf("unexpected install choice: %+v", result)
		}
	}
}
func TestWelcomeDuplicateClickCannotStartSecondAction(t *testing.T) {
	h := testWelcomeHandler()
	values := url.Values{"action": {"demo"}, "token": {h.token}}
	first := welcomePost(h, values, h.host, "http://"+h.host)
	values.Set("action", "install")
	second := welcomePost(h, values, h.host, "http://"+h.host)
	if first.Code != http.StatusOK || second.Code != http.StatusConflict || len(h.result) != 1 {
		t.Fatal("duplicate action was accepted")
	}
	if result := <-h.result; result.Choice != choiceDemo {
		t.Fatalf("first choice replaced: %+v", result)
	}
	if !strings.Contains(second.Body.String(), "Действие уже выбрано") {
		t.Fatal("no explanation of duplicate")
	}
}
func TestWelcomeInvalidUnavailableAndOversizedActionsDoNothing(t *testing.T) {
	for _, tc := range []struct {
		name, action, token  string
		canInstall, canAgent bool
	}{
		{"unknown", "surprise", "current-secret", true, true},
		{"no Windows service", "install", "current-secret", false, true},
		{"no agent", "agent", "current-secret", true, false},
		{"oversized", "demo", strings.Repeat("x", 5000), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testWelcomeHandler()
			h.canInstall = tc.canInstall
			h.canAgent = tc.canAgent
			rec := welcomePost(h, url.Values{"action": {tc.action}, "token": {tc.token}}, h.host, "")
			if rec.Code != http.StatusBadRequest || h.chosen || len(h.result) != 0 {
				t.Fatalf("unexpected action: %d", rec.Code)
			}
		})
	}
}
func TestWelcomeQuitAndAgentHandoffs(t *testing.T) {
	for action, want := range map[string]firstRunChoice{"quit": choiceQuit, "agent": choiceAgent, "setup": choiceSetup} {
		h := testWelcomeHandler()
		rec := welcomePost(h, url.Values{"action": {action}, "token": {h.token}}, h.host, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", action, rec.Code)
		}
		if result := <-h.result; result.Choice != want {
			t.Fatalf("%s: %+v", action, result)
		}
		if !strings.Contains(rec.Body.String(), "Следующий шаг") || strings.Contains(rec.Body.String(), "value=\"install\"") {
			t.Fatal("finished page still offers installation")
		}
	}
}
