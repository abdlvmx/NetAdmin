package handlers

import (
	"crypto/rand"
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/notify"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

// ticketCategories — категории заявок для портала и фильтров.
var ticketCategories = []string{
	"Оборудование", "Программное обеспечение", "Сеть / интернет",
	"Принтер / печать", "Учётная запись / доступ", "Другое",
}

// statusLabel — русская подпись статуса заявки (для писем заявителю).
// Подписи/бейджи для шаблонов живут в web.funcMap (statusRu/statusBadge/…).
func statusLabel(s string) string {
	switch s {
	case "new":
		return "Новая"
	case "in_progress":
		return "В работе"
	case "resolved":
		return "Решена"
	case "closed":
		return "Закрыта"
	}
	return s
}

// genTicketCode генерирует короткий уникальный код заявки (для отслеживания без логина).
func (a *App) genTicketCode() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // без похожих символов
	for try := 0; try < 20; try++ {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		var sb strings.Builder
		for _, x := range b {
			sb.WriteByte(alphabet[int(x)%len(alphabet)])
		}
		code := sb.String()
		var n int
		a.DB.QueryRow("SELECT COUNT(*) FROM tickets WHERE code=?", code).Scan(&n)
		if n == 0 {
			return code
		}
	}
	return ""
}

// ── СТОРОНА ИТ-СЛУЖБЫ (за логином) ──────────────────────────────────────────

type ticketRow struct {
	ID       int64
	Code     string
	Title    string
	Status   string
	Priority string
	Category string
	Reporter string
	Assignee string
	Location string
	Created  string
}

type ticketsData struct {
	User       *auth.User
	Active     string
	Rows       []ticketRow
	New        int
	InProgress int
	Open       int
	Total      int
	Categories []string
}

// TicketsPage — GET /tickets : список заявок для ИТ-службы.
func (a *App) TicketsPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := ticketsData{User: user, Active: "tickets", Categories: ticketCategories}

	rows, err := a.DB.Query(`SELECT t.id, COALESCE(t.code,''), COALESCE(t.title,''),
		COALESCE(t.status,'new'), COALESCE(t.priority,'normal'), COALESCE(t.category,''),
		COALESCE(t.reporter_name,''), COALESCE(u.full_name, u.username, ''),
		COALESCE(t.location,''), COALESCE(t.created_at,'')
		FROM tickets t LEFT JOIN users u ON u.id=t.assignee_id
		ORDER BY CASE t.status WHEN 'new' THEN 0 WHEN 'in_progress' THEN 1
			WHEN 'resolved' THEN 2 ELSE 3 END, t.created_at DESC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t ticketRow
			if rows.Scan(&t.ID, &t.Code, &t.Title, &t.Status, &t.Priority, &t.Category,
				&t.Reporter, &t.Assignee, &t.Location, &t.Created) != nil {
				continue
			}
			t.Created = tz.DateTime(t.Created)
			data.Total++
			switch t.Status {
			case "new":
				data.New++
				data.Open++
			case "in_progress":
				data.InProgress++
				data.Open++
			}
			data.Rows = append(data.Rows, t)
		}
		if err := rows.Err(); err != nil {
			log.Printf("TicketsPage: %v", err)
		}
	}
	web.RenderPage(w, "tickets", data)
}

type ticketComment struct {
	Author   string
	Body     string
	Internal bool
	Created  string
}

type ticketDetail struct {
	ID           int64
	Code         string
	Title        string
	Description  string
	Category     string
	Priority     string
	Status       string
	ReporterName string
	ReporterMail string
	ReporterTel  string
	Location     string
	EmployeeName string
	DeviceID     int64
	DeviceName   string
	AssigneeID   int64
	Created      string
	Updated      string
}

type ticketDetailData struct {
	User     *auth.User
	Active   string
	T        ticketDetail
	Comments []ticketComment
	Staff    []employeeOpt // пользователи-исполнители (id, имя)
	Devices  []employeeOpt // устройства для привязки (id, hostname)
}

// TicketDetailPage — GET /tickets/{id}.
func (a *App) TicketDetailPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var t ticketDetail
	var empID, devID, asgID sql.NullInt64
	err := a.DB.QueryRow(`SELECT t.id, COALESCE(t.code,''), COALESCE(t.title,''),
		COALESCE(t.description,''), COALESCE(t.category,''), COALESCE(t.priority,'normal'),
		COALESCE(t.status,'new'), COALESCE(t.reporter_name,''), COALESCE(t.reporter_email,''),
		COALESCE(t.reporter_phone,''), COALESCE(t.location,''), t.employee_id, t.device_id,
		t.assignee_id, COALESCE(t.created_at,''), COALESCE(t.updated_at,''),
		COALESCE(e.full_name,''), COALESCE(d.hostname,'')
		FROM tickets t
		LEFT JOIN employees e ON e.id=t.employee_id
		LEFT JOIN devices d ON d.id=t.device_id
		WHERE t.id=?`, id).Scan(&t.ID, &t.Code, &t.Title, &t.Description, &t.Category,
		&t.Priority, &t.Status, &t.ReporterName, &t.ReporterMail, &t.ReporterTel,
		&t.Location, &empID, &devID, &asgID, &t.Created, &t.Updated, &t.EmployeeName, &t.DeviceName)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	t.DeviceID, t.AssigneeID = devID.Int64, asgID.Int64
	t.Created, t.Updated = tz.DateTime(t.Created), tz.DateTime(t.Updated)

	data := ticketDetailData{User: user, Active: "tickets", T: t}
	if rows, err := a.DB.Query(`SELECT COALESCE(author_name,''), COALESCE(body,''),
		is_internal, COALESCE(created_at,'') FROM ticket_comments WHERE ticket_id=?
		ORDER BY created_at`, id); err == nil {
		for rows.Next() {
			var c ticketComment
			var internal int
			var created string
			if rows.Scan(&c.Author, &c.Body, &internal, &created) == nil {
				c.Internal = internal == 1
				c.Created = tz.DateTime(created)
				data.Comments = append(data.Comments, c)
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("TicketDetailPage: %v", err)
		}
		rows.Close()
	}
	// исполнители — активные пользователи системы
	if rows, err := a.DB.Query(`SELECT id, COALESCE(full_name, username) FROM users
		WHERE is_active=1 AND role IN ('admin','user') ORDER BY full_name, username`); err == nil {
		for rows.Next() {
			var o employeeOpt
			if rows.Scan(&o.ID, &o.Name) == nil {
				data.Staff = append(data.Staff, o)
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("TicketDetailPage: %v", err)
		}
		rows.Close()
	}
	// устройства для привязки
	if rows, err := a.DB.Query(`SELECT id, hostname FROM devices ORDER BY hostname`); err == nil {
		for rows.Next() {
			var o employeeOpt
			if rows.Scan(&o.ID, &o.Name) == nil {
				data.Devices = append(data.Devices, o)
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("TicketDetailPage: %v", err)
		}
		rows.Close()
	}
	web.RenderPage(w, "ticket_detail", data)
}

// TicketUpdate — POST /tickets/{id}/update : исполнитель/приоритет/категория/устройство (CanWrite).
func (a *App) TicketUpdate(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = r.ParseForm()
	asg := nullableID(r.FormValue("assignee_id"))
	dev := nullableID(r.FormValue("device_id"))
	priority := r.FormValue("priority")
	if priority != "low" && priority != "high" {
		priority = "normal"
	}
	a.DB.Exec(`UPDATE tickets SET assignee_id=?, device_id=?, priority=?, category=?,
		location=?, updated_at=datetime('now') WHERE id=?`,
		asg, dev, priority, strings.TrimSpace(r.FormValue("category")),
		strings.TrimSpace(r.FormValue("location")), id)
	auth.LogAction(a.DB, user.ID, "ticket_update", "ticket #"+strconv.FormatInt(id, 10), "")
	http.Redirect(w, r, "/tickets/"+strconv.FormatInt(id, 10)+"?message=saved", http.StatusSeeOther)
}

// TicketStatus — POST /tickets/{id}/status : смена статуса (CanWrite) + письмо заявителю.
func (a *App) TicketStatus(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	status := r.FormValue("status")
	if status != "new" && status != "in_progress" && status != "resolved" && status != "closed" {
		http.Error(w, "bad status", http.StatusBadRequest)
		return
	}
	if status == "closed" || status == "resolved" {
		a.DB.Exec("UPDATE tickets SET status=?, closed_at=datetime('now'), updated_at=datetime('now') WHERE id=?", status, id)
	} else {
		a.DB.Exec("UPDATE tickets SET status=?, closed_at=NULL, updated_at=datetime('now') WHERE id=?", status, id)
	}
	auth.LogAction(a.DB, user.ID, "ticket_status", "ticket #"+strconv.FormatInt(id, 10), status)

	// уведомляем заявителя о смене статуса
	var code, title, mail string
	a.DB.QueryRow("SELECT COALESCE(code,''), COALESCE(title,''), COALESCE(reporter_email,'') FROM tickets WHERE id=?", id).
		Scan(&code, &title, &mail)
	if mail != "" {
		notify.Email(mail, "Заявка "+code+": "+statusLabel(status),
			"Статус вашей заявки «"+title+"» изменён на: "+statusLabel(status)+
				".\n\nОтследить: откройте портал заявок и введите код "+code+".")
	}
	http.Redirect(w, r, "/tickets/"+strconv.FormatInt(id, 10)+"?message=status", http.StatusSeeOther)
}

// TicketComment — POST /tickets/{id}/comment : комментарий ИТ-службы (CanWrite).
// Публичный комментарий уходит письмом заявителю; внутренняя заметка — нет.
func (a *App) TicketComment(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	body := strings.TrimSpace(r.FormValue("body"))
	if body == "" {
		http.Redirect(w, r, "/tickets/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
		return
	}
	internal := 0
	if r.FormValue("internal") != "" {
		internal = 1
	}
	name := user.FullName
	if name == "" {
		name = user.Username
	}
	a.DB.Exec(`INSERT INTO ticket_comments (ticket_id, author_user_id, author_name, body, is_internal)
		VALUES (?,?,?,?,?)`, id, user.ID, name, body, internal)
	a.DB.Exec("UPDATE tickets SET updated_at=datetime('now') WHERE id=?", id)

	if internal == 0 {
		var code, mail string
		a.DB.QueryRow("SELECT COALESCE(code,''), COALESCE(reporter_email,'') FROM tickets WHERE id=?", id).Scan(&code, &mail)
		if mail != "" {
			notify.Email(mail, "Заявка "+code+": ответ ИТ-службы",
				name+" ответил(а) по вашей заявке:\n\n"+body+"\n\nКод для отслеживания: "+code)
		}
	}
	http.Redirect(w, r, "/tickets/"+strconv.FormatInt(id, 10)+"?message=comment", http.StatusSeeOther)
}

// nullableID превращает строку формы в *int64 (пустая → NULL).
func nullableID(s string) any {
	if v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && v > 0 {
		return v
	}
	return nil
}
