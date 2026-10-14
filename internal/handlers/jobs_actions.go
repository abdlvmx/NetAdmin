package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"netadmin/internal/deviceaccess"
	"netadmin/internal/edition"
	"os"
	"path/filepath"
	"strconv"
)

func (a *App) CancelJob(w http.ResponseWriter, r *http.Request) {
	u := jobsAccount(a, w, r, true)
	if u == nil {
		return
	}
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if _, err = a.jobByID(r, u, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Задание недоступно", 503)
		}
		return
	}
	if r.FormValue("confirm") != "1" {
		http.Error(w, "Подтвердите отмену оставшихся заданий", 400)
		return
	}
	tx, err := a.DB.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "Отмена не сохранена", 503)
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), `UPDATE agent_tasks SET
	status=CASE WHEN status='pending' THEN 'cancelled' ELSE status END,
	result=CASE WHEN status='pending' THEN 'Отменено пользователем до выдачи агенту.' ELSE result END,
	exit_code=CASE WHEN status='pending' THEN 125 ELSE exit_code END,
	done_at=CASE WHEN status='pending' THEN datetime('now') ELSE done_at END,
	cancel_requested=CASE WHEN status='pending' THEN 0 ELSE 1 END
	WHERE job_id=? AND (`+a.deviceScopeSQL("agent_tasks.device_id")+`) AND (status='pending' OR (task_protocol=2 AND status IN ('sent','running') AND cancel_requested=0))`, id)
	if err != nil {
		http.Error(w, "Отмена не сохранена", 503)
		return
	}
	n, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "Отмена не сохранена", 503)
		return
	}
	if n == 0 {
		http.Error(w, "Не осталось доступных заданий для отмены. Обновите страницу.", 409)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO audit_log(user_id,action,target,detail) VALUES(?,'job_cancel',?,?)", u.ID, fmt.Sprint(id), fmt.Sprintf("targets=%d", n)); err != nil {
		http.Error(w, "Отмена не сохранена", 503)
		return
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "Отмена не сохранена", 503)
		return
	}
	http.Redirect(w, r, "/jobs/"+strconv.FormatInt(id, 10)+"?result=cancelled", 303)
}

// A retry never accepts a browser-supplied command or package payload. It uses
// an immutable failed task and checks the current library/package and access.
func (a *App) retrySpec(r *http.Request, tx *sql.Tx, spec taskSpec) error {
	switch spec.Kind {
	case "command":
		if _, ok := cmdByKey(spec.Payload); !ok {
			return errors.New("Команда больше не доступна в библиотеке.")
		}
	case "check", "reboot", "shutdown", "logoff":
		if spec.Payload != "" {
			return errors.New("Состав задания не поддерживает повтор.")
		}
	case "install", "selfupdate":
		var old, current installPayload
		if json.Unmarshal([]byte(spec.Payload), &old) != nil || old.ID != spec.PackageID || old.ID <= 0 {
			return errors.New("Не удалось проверить дистрибутив задания.")
		}
		if err := tx.QueryRowContext(r.Context(), `SELECT id,COALESCE(name,''),COALESCE(kind,''),COALESCE(filename,''),COALESCE(sha256,''),COALESCE(install_args,'') FROM packages WHERE id=?`, old.ID).Scan(&current.ID, &current.Name, &current.Kind, &current.Filename, &current.SHA256, &current.Args); err != nil {
			return errors.New("Дистрибутив недоступен. Создайте новое задание после загрузки файла.")
		}
		if old.Kind != current.Kind || old.Filename != current.Filename || old.SHA256 == "" || old.SHA256 != current.SHA256 || (spec.Kind == "install" && old.Args != current.Args) {
			return errors.New("Дистрибутив или параметры изменились. Создайте новое задание.")
		}
		if current.Filename == "" || filepath.Base(current.Filename) != current.Filename {
			return errors.New("Файл дистрибутива недоступен.")
		}
		file := filepath.Join(packagesDir(), current.Filename)
		if st, err := os.Stat(file); err != nil || !st.Mode().IsRegular() {
			return errors.New("Файл дистрибутива недоступен.")
		}
		f, err := os.Open(file)
		if err != nil {
			return errors.New("Файл дистрибутива недоступен.")
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, io.LimitReader(f, (1<<30)+1))
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != old.SHA256 {
			return errors.New("Содержимое дистрибутива изменилось. Загрузите проверенный файл и создайте новое задание.")
		}
		if spec.Kind == "selfupdate" {
			if binaryEdition, err := readAgentEdition(file); err != nil || binaryEdition != edition.ID {
				return errors.New("Сборка агента не соответствует редакции сервера.")
			}
		}
	default:
		return errors.New("Этот вид задания не поддерживает повтор.")
	}
	return nil
}

func (a *App) RetryJob(w http.ResponseWriter, r *http.Request) {
	u := jobsAccount(a, w, r, true)
	if u == nil {
		return
	}
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	j, err := a.jobByID(r, u, id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Задание недоступно", 503)
		return
	}
	if !jobCanRepeat(u, j.Kind) {
		http.Error(w, "forbidden", 403)
		return
	}
	if err = r.ParseForm(); err != nil || r.FormValue("confirm") != "1" {
		http.Error(w, "Подтвердите повторное выполнение выбранных действий", 400)
		return
	}
	sources, err := deviceaccess.IDs(r.Form["task"], 5000)
	if err != nil || len(sources) == 0 {
		http.Error(w, "Выберите задания с ошибкой", 400)
		return
	}
	tx, err := a.DB.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "Повтор не поставлен", 503)
		return
	}
	defer tx.Rollback()
	var spec taskSpec
	var targets []int64
	for i, source := range sources {
		var current taskSpec
		var device int64
		var status string
		var retry int
		var token string
		err = tx.QueryRowContext(r.Context(), `SELECT t.device_id,COALESCE(t.kind,''),COALESCE(t.payload,''),COALESCE(t.label,''),COALESCE(t.package_id,0),COALESCE(t.status,''),
		EXISTS(SELECT 1 FROM agent_tasks repeated WHERE repeated.retry_of=t.id),COALESCE(d.agent_token,'')
		FROM agent_tasks t JOIN devices d ON d.id=t.device_id WHERE t.id=? AND t.job_id=? AND (`+a.deviceScopeSQL("t.device_id")+`)`, source, id).Scan(&device, &current.Kind, &current.Payload, &current.Label, &current.PackageID, &status, &retry, &token)
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Выборка содержит недоступные задания. Ни одно действие не поставлено.", 403)
			return
		}
		if err != nil {
			http.Error(w, "Повтор не поставлен", 503)
			return
		}
		if status != "failed" || retry != 0 || token == "" || current.Kind != j.Kind {
			http.Error(w, "Состояние задания изменилось, оно уже повторено или агент недоступен. Обновите страницу.", 409)
			return
		}
		if i == 0 {
			spec = current
		} else if spec != current {
			http.Error(w, "Состав заданий различается. Повторите их отдельно.", 409)
			return
		}
		targets = append(targets, device)
	}
	if err = a.retrySpec(r, tx, spec); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	job, err := a.enqueueJobTx(r.Context(), tx, targets, spec, u.ID, j.ID, sources)
	if err != nil {
		http.Error(w, "Повтор не поставлен. Обновите страницу и повторите действие.", 409)
		return
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "Повтор не поставлен", 503)
		return
	}
	http.Redirect(w, r, "/jobs/"+strconv.FormatInt(job.ID, 10)+"?result=retried", 303)
}
