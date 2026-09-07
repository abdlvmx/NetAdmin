package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netadmin/internal/auth"
	"netadmin/internal/config"
)

// Одноразовые коды регистрации.
//
// Постоянный токен агента из config.json действует до ручной ротации. Он
// удобен для скриптов раскатки, но для установки руками — плохой выбор: строка
// с ним остаётся в истории консоли, в переписке, в заметках, и отозвать её
// можно только сменив токен всему парку сразу.
//
// Код решает то же самое иначе: живёт заданный срок, считает установки и
// перестаёт подходить, когда одно из двух кончилось. Устройству он нужен
// однажды — дальше оно работает по персональному токену.

// Пределы, чтобы «код на всякий случай подольше» не превращался во второй
// постоянный токен.
const (
	maxCodeTTL   = 24 * time.Hour
	maxCodeUses  = 200
	codeTimeLay  = "2006-01-02 15:04:05" // как datetime('now') в SQLite
	codeKeepDays = 7                     // сколько держать истёкшие, чтобы были видны в журнале
)

// enrollCode — код в том виде, в каком его показывает страница настроек.
type enrollCode struct {
	ID        int64
	Code      string
	Left      int    // сколько установок осталось; -1 — без ограничения
	ExpiresIn string // «через 42 мин»
	Command   string // готовая команда установки с этим кодом
}

// activeEnrollKeys возвращает коды, которыми сейчас можно зарегистрировать
// устройство. Постоянный токен сюда не входит — его добавляет вызывающий.
func (a *App) activeEnrollKeys() []string {
	rows, err := a.DB.Query(`SELECT code FROM enroll_codes
		WHERE revoked=0 AND expires_at > datetime('now')
		  AND (max_uses=0 OR used_count < max_uses)`)
	if err != nil {
		log.Printf("коды регистрации: %v", err)
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if rows.Scan(&c) == nil && c != "" {
			out = append(out, c)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("коды регистрации: %v", err)
	}
	return out
}

// useEnrollCode отмечает израсходованную установку.
//
// Считается только удачная регистрация устройства: до неё агент успевает
// сделать несколько подписанных запросов тем же ключом, и списывать установку
// за каждый значило бы, что код на пять машин кончается на первой.
func (a *App) useEnrollCode(code string) {
	if code == "" {
		return
	}
	if _, err := a.DB.Exec(
		"UPDATE enroll_codes SET used_count=used_count+1 WHERE code=?", code); err != nil {
		log.Printf("коды регистрации: %v", err)
	}
}

// listEnrollCodes — действующие коды для страницы настроек.
func (a *App) listEnrollCodes(server string) []enrollCode {
	rows, err := a.DB.Query(`SELECT id, code, max_uses, used_count, expires_at
		FROM enroll_codes
		WHERE revoked=0 AND expires_at > datetime('now')
		  AND (max_uses=0 OR used_count < max_uses)
		ORDER BY id DESC`)
	if err != nil {
		log.Printf("коды регистрации: %v", err)
		return nil
	}
	defer rows.Close()

	var out []enrollCode
	for rows.Next() {
		var (
			id                 int64
			code, expires      string
			maxUses, usedCount int
		)
		if rows.Scan(&id, &code, &maxUses, &usedCount, &expires) != nil {
			continue
		}
		left := -1
		if maxUses > 0 {
			left = maxUses - usedCount
		}
		out = append(out, enrollCode{
			ID: id, Code: code, Left: left,
			ExpiresIn: humanLeft(expires),
			Command:   enrollCommand(server, code),
		})
	}
	if err := rows.Err(); err != nil {
		log.Printf("коды регистрации: %v", err)
	}
	return out
}

// humanLeft переводит время истечения в «через 42 мин».
func humanLeft(expires string) string {
	t, err := time.Parse(codeTimeLay, expires)
	if err != nil {
		return "—"
	}
	d := time.Until(t.UTC())
	switch {
	case d <= 0:
		return "истёк"
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes())+1)
	default:
		return fmt.Sprintf("%d ч %d мин", int(d.Hours()), int(d.Minutes())%60)
	}
}

// CreateEnrollCode — POST /settings/enroll-code (admin).
func (a *App) CreateEnrollCode(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()

	minutes, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("minutes")))
	if minutes <= 0 {
		minutes = 60
	}
	if d := time.Duration(minutes) * time.Minute; d > maxCodeTTL {
		minutes = int(maxCodeTTL / time.Minute)
	}
	uses, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("uses")))
	if uses <= 0 {
		uses = 1
	}
	if uses > maxCodeUses {
		uses = maxCodeUses
	}

	code := config.GenerateToken()
	expires := time.Now().UTC().Add(time.Duration(minutes) * time.Minute).Format(codeTimeLay)
	if _, err := a.DB.Exec(`INSERT INTO enroll_codes (code, expires_at, max_uses, created_by)
		VALUES (?,?,?,?)`, code, expires, uses, user.ID); err != nil {
		settingsError(w, r, "Не удалось создать код: "+err.Error())
		return
	}
	auth.LogAction(a.DB, user.ID, "create_enroll_code", "settings",
		fmt.Sprintf("на %d мин, установок: %d", minutes, uses))
	http.Redirect(w, r, "/settings?message=code_created", http.StatusSeeOther)
}

// RevokeEnrollCode — POST /settings/enroll-code/{id}/revoke (admin).
func (a *App) RevokeEnrollCode(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if _, err := a.DB.Exec("UPDATE enroll_codes SET revoked=1 WHERE id=?", id); err != nil {
		settingsError(w, r, "Не удалось отозвать код: "+err.Error())
		return
	}
	auth.LogAction(a.DB, user.ID, "revoke_enroll_code", strconv.FormatInt(id, 10), "")
	http.Redirect(w, r, "/settings?message=code_revoked", http.StatusSeeOther)
}

// PurgeEnrollCodes убирает давно истёкшие коды. Отработавшие держатся ещё
// неделю: по ним видно в журнале, чем именно регистрировали машину.
func PurgeEnrollCodes(d *sql.DB) {
	if _, err := d.Exec(
		"DELETE FROM enroll_codes WHERE expires_at < datetime('now', ?)",
		fmt.Sprintf("-%d days", codeKeepDays)); err != nil {
		log.Printf("уборка кодов регистрации: %v", err)
	}
}

// isEnrollCode сообщает, что запрос подписан одноразовым кодом, а не постоянным
// токеном из настроек. От этого зависит, разрешена ли переустановка агента на
// уже зарегистрированной машине.
func (a *App) isEnrollCode(key string) bool {
	if key == "" {
		return false
	}
	var n int
	if err := a.DB.QueryRow("SELECT COUNT(*) FROM enroll_codes WHERE code=?", key).Scan(&n); err != nil {
		log.Printf("коды регистрации: %v", err)
		return false
	}
	return n > 0
}
