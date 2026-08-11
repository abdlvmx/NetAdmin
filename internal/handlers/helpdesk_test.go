package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func helpRoutes(a *App) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /help/submit", a.HelpSubmit)
	mux.HandleFunc("GET /help/track", a.HelpTrack)
	mux.HandleFunc("POST /help/track/reply", a.HelpReply)
	return httptest.NewServer(mux)
}

func TestHelpSubmitCreatesTicket(t *testing.T) {
	app := newTestApp(t) // config.HelpdeskEnabled=true для свежей БД
	srv := helpRoutes(app)
	defer srv.Close()

	resp, err := srv.Client().PostForm(srv.URL+"/help/submit", url.Values{
		"reporter_name":  {"Иванов Иван"},
		"reporter_email": {"ivanov@org.ru"},
		"location":       {"каб. 304"},
		"category":       {"Принтер / печать"},
		"description":    {"Не печатает принтер на 3 этаже"},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	resp.Body.Close()

	if n := countRows(app, "SELECT COUNT(*) FROM tickets WHERE status='new'"); n != 1 {
		t.Fatalf("ожидалась 1 новая заявка, получено %d", n)
	}
	var code, title string
	app.DB.QueryRow("SELECT code, title FROM tickets LIMIT 1").Scan(&code, &title)
	if code == "" {
		t.Fatalf("у заявки должен быть код для отслеживания")
	}
	if title != "Не печатает принтер на 3 этаже" {
		t.Fatalf("заголовок должен автозаполниться из описания, получено %q", title)
	}
}

func TestHelpSubmitRequiresIdentityAndProblem(t *testing.T) {
	app := newTestApp(t)
	srv := helpRoutes(app)
	defer srv.Close()

	// без имени и без описания — заявка не создаётся (форма возвращается с ошибкой)
	resp, _ := srv.Client().PostForm(srv.URL+"/help/submit", url.Values{"reporter_email": {"x@y.ru"}})
	resp.Body.Close()
	if n := countRows(app, "SELECT COUNT(*) FROM tickets"); n != 0 {
		t.Fatalf("пустая заявка не должна сохраняться, получено %d", n)
	}
}

func TestHelpReplyReopensResolved(t *testing.T) {
	app := newTestApp(t)
	srv := helpRoutes(app)
	defer srv.Close()

	app.DB.Exec(`INSERT INTO tickets (code, title, status, reporter_name)
		VALUES ('ABC123','Тест','resolved','Петров')`)

	resp, err := srv.Client().PostForm(srv.URL+"/help/track/reply", url.Values{
		"code": {"ABC123"}, "body": {"Проблема повторилась снова"},
	})
	if err != nil {
		t.Fatalf("reply: %v", err)
	}
	resp.Body.Close()

	var status string
	app.DB.QueryRow("SELECT status FROM tickets WHERE code='ABC123'").Scan(&status)
	if status != "in_progress" {
		t.Fatalf("ответ заявителя должен переоткрыть решённую заявку (in_progress), получено %q", status)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM ticket_comments WHERE is_internal=0"); n != 1 {
		t.Fatalf("ожидался 1 публичный комментарий заявителя, получено %d", n)
	}
}
