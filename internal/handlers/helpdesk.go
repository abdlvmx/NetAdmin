package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"netadmin/internal/config"
	"netadmin/internal/notify"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

// Публичный портал заявок (/help) — без логина, для сотрудников организации.
// Это helpdesk-учёт обращений, не средство защиты информации.

type helpPageData struct {
	OrgName    string
	Enabled    bool
	Employees  []employeeOpt
	Categories []string
	Error      string
	Values     map[string]string // для повторного заполнения формы при ошибке
}

// HelpPage — GET /help : форма подачи заявки.
func (a *App) HelpPage(w http.ResponseWriter, r *http.Request) {
	cfg := config.Load()
	web.Render(w, "help.html", helpPageData{
		OrgName:    cfg.OrganizationName,
		Enabled:    cfg.HelpdeskEnabled,
		Employees:  a.listEmployees(),
		Categories: ticketCategories,
		Values:     map[string]string{},
	})
}

// HelpSubmit — POST /help/submit : приём заявки от сотрудника.
func (a *App) HelpSubmit(w http.ResponseWriter, r *http.Request) {
	cfg := config.Load()
	if !cfg.HelpdeskEnabled {
		http.Error(w, "приём заявок отключён", http.StatusForbidden)
		return
	}
	if !helpdeskLimiter.allow(clientIP(r)) {
		http.Error(w, "слишком много заявок, попробуйте позже", http.StatusTooManyRequests)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("reporter_name"))
	email := strings.TrimSpace(r.FormValue("reporter_email"))
	phone := strings.TrimSpace(r.FormValue("reporter_phone"))
	location := strings.TrimSpace(r.FormValue("location"))
	category := strings.TrimSpace(r.FormValue("category"))
	title := strings.TrimSpace(r.FormValue("title"))
	desc := strings.TrimSpace(r.FormValue("description"))
	empID := nullableID(r.FormValue("employee_id"))

	// если выбран сотрудник из справочника, а имя не введено — подставим из справочника
	if name == "" {
		if id, ok := empID.(int64); ok {
			a.DB.QueryRow("SELECT full_name FROM employees WHERE id=?", id).Scan(&name)
		}
	}

	render := func(errMsg string) {
		web.Render(w, "help.html", helpPageData{
			OrgName: cfg.OrganizationName, Enabled: true,
			Employees: a.listEmployees(), Categories: ticketCategories, Error: errMsg,
			Values: map[string]string{
				"reporter_name": name, "reporter_email": email, "reporter_phone": phone,
				"location": location, "category": category, "title": title, "description": desc,
			},
		})
	}
	if name == "" {
		render("Укажите, как к вам обращаться (ФИО).")
		return
	}
	if title == "" && desc == "" {
		render("Опишите проблему.")
		return
	}
	if title == "" {
		title = firstLine(desc, 80)
	}

	code := a.genTicketCode()
	res, err := a.DB.Exec(`INSERT INTO tickets
		(code, title, description, category, status, priority, employee_id,
		 reporter_name, reporter_email, reporter_phone, location)
		VALUES (?,?,?,?, 'new', 'normal', ?,?,?,?,?)`,
		code, title, desc, category, empID, name, email, phone, location)
	if err != nil {
		render("Не удалось сохранить заявку. Сообщите в ИТ-отдел.")
		return
	}
	id, _ := res.LastInsertId()

	// уведомляем ИТ-службу (на настроенный SMTP-ящик)
	contact := email
	if phone != "" {
		if contact != "" {
			contact += ", "
		}
		contact += phone
	}
	notify.Message("Новая заявка " + code + ": " + title + "\n\n" +
		"От: " + name + locDetail(location) + contactDetail(contact) + "\n\n" + desc +
		"\n\nОткрыть: /tickets/" + strconv.FormatInt(id, 10))

	// Подтверждение заявителю. Код показывается только на странице после
	// отправки: закрыв вкладку, человек терял единственный способ отследить
	// обращение и писал заново.
	notify.Email(email, "Заявка "+code+" принята",
		"Здравствуйте, "+name+".\n\n"+
			"Ваше обращение принято, номер заявки: "+code+"\n"+
			"Тема: "+title+"\n\n"+
			"Сохраните этот код — по нему можно посмотреть статус и написать "+
			"в ИТ-службу на портале заявок, в разделе «Отследить заявку».\n\n"+
			"Отвечать на это письмо не нужно.")

	http.Redirect(w, r, "/help/track?code="+code+"&new=1", http.StatusSeeOther)
}

type helpTrackData struct {
	OrgName  string
	New      bool
	NotFound bool
	Code     string
	Found    bool
	Title    string
	Status   string
	StatusRu string
	Category string
	Created  string
	Updated  string
	Comments []ticketComment
}

// HelpTrack — GET /help/track?code=… : статус заявки по коду (без логина).
func (a *App) HelpTrack(w http.ResponseWriter, r *http.Request) {
	cfg := config.Load()
	code := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("code")))
	data := helpTrackData{OrgName: cfg.OrganizationName, New: r.URL.Query().Get("new") == "1", Code: code}
	// код заявки — единственная защита чужого обращения от просмотра,
	// поэтому перебор кодов ограничиваем по частоте
	if code != "" && !trackLimiter.allow(clientIP(r)) {
		http.Error(w, "слишком много запросов, попробуйте позже", http.StatusTooManyRequests)
		return
	}
	if code == "" {
		web.Render(w, "help_track.html", data)
		return
	}
	var id int64
	err := a.DB.QueryRow(`SELECT id, COALESCE(title,''), COALESCE(status,'new'),
		COALESCE(category,''), COALESCE(created_at,''), COALESCE(updated_at,'')
		FROM tickets WHERE code=?`, code).
		Scan(&id, &data.Title, &data.Status, &data.Category, &data.Created, &data.Updated)
	if err != nil {
		data.NotFound = true
		web.Render(w, "help_track.html", data)
		return
	}
	data.Found = true
	data.StatusRu = statusLabel(data.Status)
	data.Created = tz.DateTime(data.Created)
	data.Updated = tz.DateTime(data.Updated)
	// публичные комментарии (не внутренние заметки)
	if rows, err := a.DB.Query(`SELECT COALESCE(author_name,''), COALESCE(body,''),
		COALESCE(created_at,'') FROM ticket_comments WHERE ticket_id=? AND is_internal=0
		ORDER BY created_at`, id); err == nil {
		for rows.Next() {
			var c ticketComment
			var created string
			if rows.Scan(&c.Author, &c.Body, &created) == nil {
				c.Created = tz.DateTime(created)
				data.Comments = append(data.Comments, c)
			}
		}
		rows.Close()
	}
	web.Render(w, "help_track.html", data)
}

// HelpReply — POST /help/track/reply : сообщение заявителя по существующей заявке.
func (a *App) HelpReply(w http.ResponseWriter, r *http.Request) {
	if !config.Load().HelpdeskEnabled {
		http.Error(w, "приём заявок отключён", http.StatusForbidden)
		return
	}
	if !helpdeskLimiter.allow(clientIP(r)) {
		http.Error(w, "слишком часто, попробуйте позже", http.StatusTooManyRequests)
		return
	}
	_ = r.ParseForm()
	code := strings.ToUpper(strings.TrimSpace(r.FormValue("code")))
	body := strings.TrimSpace(r.FormValue("body"))
	var id int64
	var name, status string
	if a.DB.QueryRow("SELECT id, COALESCE(reporter_name,''), COALESCE(status,'new') FROM tickets WHERE code=?", code).
		Scan(&id, &name, &status) != nil {
		http.NotFound(w, r)
		return
	}
	if body != "" {
		if name == "" {
			name = "Заявитель"
		}
		a.DB.Exec(`INSERT INTO ticket_comments (ticket_id, author_name, body, is_internal)
			VALUES (?,?,?,0)`, id, name, body)
		// ответ заявителя по решённой/закрытой заявке снова открывает её
		if status == "resolved" || status == "closed" {
			a.DB.Exec("UPDATE tickets SET status='in_progress', closed_at=NULL, updated_at=datetime('now') WHERE id=?", id)
		} else {
			a.DB.Exec("UPDATE tickets SET updated_at=datetime('now') WHERE id=?", id)
		}
		notify.Message("Сообщение по заявке " + code + " от заявителя:\n\n" + body + "\n\nОткрыть: /tickets/" + strconv.FormatInt(id, 10))
	}
	http.Redirect(w, r, "/help/track?code="+code, http.StatusSeeOther)
}

// firstLine берёт первую строку текста, обрезая до n символов (для авто-заголовка).
func firstLine(s string, n int) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func locDetail(loc string) string {
	if loc == "" {
		return ""
	}
	return " · кабинет: " + loc
}

func contactDetail(c string) string {
	if c == "" {
		return ""
	}
	return " · контакт: " + c
}
