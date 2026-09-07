package handlers

import (
	"net/http"
	"strings"
	"testing"

	"netadmin/internal/agentbin"
)

// withBuildMatch подставляет результат сверки встроенного агента с сервером:
// в тестовом окружении встроенной сборки нет, и сверять нечего.
func withBuildMatch(t *testing.T, m agentbin.Match) {
	t.Helper()
	prev := agentBuildMatch
	agentBuildMatch = func() agentbin.Match { return m }
	t.Cleanup(func() { agentBuildMatch = prev })
}

// settingsPage отдаёт разметку страницы настроек администратору.
func settingsPage(t *testing.T, app *App) string {
	t.Helper()
	rec := adminRequest(t, app, "GET", "http://192.168.1.64:8765/settings")
	if rec.Code != http.StatusOK {
		t.Fatalf("страница настроек вернула %d", rec.Code)
	}
	return rec.Body.String()
}

// Сервер, собранный не в том порядке, должен сказать об этом на той же
// странице, где предлагает установить агента.
//
// Порядок сборки — агент первым, сервер вторым — ничем не проверялся, и промах
// молчаливый: сервер трое суток раздавал сборку агента трёхдневной давности,
// а обнаружилось это только когда та отказалась ставиться поверх своей службы.
func TestSettingsWarnsAboutStaleEmbeddedAgent(t *testing.T) {
	app := newTestApp(t)
	withEmbeddedAgent(t, "встроенная сборка", "embeddedsha")
	withBuildMatch(t, agentbin.MatchStale)

	body := settingsPage(t, app)
	if !strings.Contains(body, "Встроенная сборка агента устарела") {
		t.Error("страница молчит о том, что внутри сервера старая сборка агента")
	}
}

// Но жаловаться нельзя, когда отдаётся не встроенная сборка: загруженная в
// «Установку ПО» важнее, и тогда возраст встроенной никого не касается.
//
// Предупреждение, которое горит там, где всё в порядке, перестают читать — и
// оно не сработает там, где нужно.
func TestNoStaleWarningWhenUploadedBuildIsServed(t *testing.T) {
	app := newTestApp(t)
	withEmbeddedAgent(t, "встроенная сборка", "embeddedsha")
	withBuildMatch(t, agentbin.MatchStale)
	addAgentBuild(t, app, "agent.exe", "загруженная сборка", "uploadedsha")

	body := settingsPage(t, app)
	if strings.Contains(body, "Встроенная сборка агента устарела") {
		t.Error("предупреждение показано, хотя сервер отдаёт загруженную сборку")
	}
}

// И молчит, когда сверка ничего не показала: сборка без git или без агента
// внутри — не повод обвинять.
func TestNoStaleWarningWithoutComparison(t *testing.T) {
	app := newTestApp(t)
	withEmbeddedAgent(t, "встроенная сборка", "embeddedsha")
	withBuildMatch(t, agentbin.MatchUnknown)

	body := settingsPage(t, app)
	if strings.Contains(body, "Встроенная сборка агента устарела") {
		t.Error("предупреждение показано, хотя сравнить было не с чем")
	}
}
