package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

// Смоук-тесты: страницы заявок и портала исполняются без ошибок шаблона.
func TestTicketTemplatesRender(t *testing.T) {
	admin := &auth.User{ID: 1, Username: "admin", Role: "admin"}

	checks := []struct {
		name   string
		render func(*httptest.ResponseRecorder)
		want   string
	}{
		{"tickets", func(rec *httptest.ResponseRecorder) {
			web.RenderPage(rec, "tickets", ticketsData{
				User: admin, Active: "tickets", Total: 1, New: 1, Open: 1,
				Categories: ticketCategories,
				Rows: []ticketRow{{ID: 1, Code: "ABC123", Title: "Принтер", Status: "new",
					Priority: "normal", Reporter: "Иванов", Created: "01.01 10:00"}},
			})
		}, "Заявки"},
		{"ticket_detail", func(rec *httptest.ResponseRecorder) {
			web.RenderPage(rec, "ticket_detail", ticketDetailData{
				User: admin, Active: "tickets",
				T:        ticketDetail{ID: 1, Code: "ABC123", Title: "Принтер", Status: "new", Priority: "normal", ReporterName: "Иванов"},
				Comments: []ticketComment{{Author: "Иванов", Body: "Текст", Created: "01.01 10:00"}},
				Staff:    []employeeOpt{{ID: 2, Name: "Сидоров"}},
				Devices:  []employeeOpt{{ID: 3, Name: "PC-1"}},
			})
		}, "Переписка"},
		{"help", func(rec *httptest.ResponseRecorder) {
			web.Render(rec, "help.html", helpPageData{
				OrgName: "Org", Enabled: true, Categories: ticketCategories,
				Employees: []employeeOpt{{ID: 1, Name: "Иванов", Dept: "Бухгалтерия"}},
				Values:    map[string]string{},
			})
		}, "Отправить заявку"},
		{"help_track", func(rec *httptest.ResponseRecorder) {
			web.Render(rec, "help_track.html", helpTrackData{
				OrgName: "Org", Found: true, Code: "ABC123", Title: "Принтер",
				Status: "in_progress", StatusRu: "В работе", Created: "01.01 10:00",
				Comments: []ticketComment{{Author: "Сидоров", Body: "Смотрим", Created: "01.01 11:00"}},
			})
		}, "Статус заявки"},
	}

	for _, c := range checks {
		rec := httptest.NewRecorder()
		c.render(rec)
		body := rec.Body.String()
		if strings.Contains(body, "template error") {
			t.Fatalf("%s: ошибка выполнения шаблона: %s", c.name, body)
		}
		if !strings.Contains(body, c.want) {
			t.Fatalf("%s: в выводе нет %q", c.name, c.want)
		}
	}
}
