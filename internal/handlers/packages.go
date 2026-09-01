package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

// packagesDir — каталог хранения загруженных дистрибутивов.
func packagesDir() string {
	d := filepath.Join(config.DataDir(), "packages")
	_ = os.MkdirAll(d, 0o755)
	return d
}

// installPayload — то, что уходит агенту в задаче установки (payload задачи).
type installPayload struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Args     string `json:"args"`
}

// kindByExt определяет тип дистрибутива по расширению.
func kindByExt(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".msi":
		return "msi"
	case ".ps1", ".bat", ".cmd":
		return "script"
	default:
		return "exe"
	}
}

type pkgRow struct {
	ID       int64
	Name     string
	Original string
	Kind     string
	SizeMB   string
	Args     string
	Created  string
}

type deployRow struct {
	Device  string
	Package string
	Status  string
	Result  string
	Created string
}

// verRow — сколько машин на какой версии агента.
type verRow struct {
	Version string
	Count   int
}

type packagesData struct {
	User          *auth.User
	Active        string
	Packages      []pkgRow
	Devices       []employeeOpt
	Recent        []deployRow
	AgentVersions []verRow
	Msg           string
	Err           string
}

// PackagesPage — GET /packages : дистрибутивы, загрузка, раздача, история.
func (a *App) PackagesPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := packagesData{User: user, Active: "packages",
		Msg: r.URL.Query().Get("message"), Err: r.URL.Query().Get("error")}

	if rows, err := a.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(original_name,''),
		COALESCE(kind,''), size, COALESCE(install_args,''), COALESCE(created_at,'')
		FROM packages ORDER BY id DESC`); err == nil {
		for rows.Next() {
			var p pkgRow
			var size int64
			var created string
			if rows.Scan(&p.ID, &p.Name, &p.Original, &p.Kind, &size, &p.Args, &created) == nil {
				p.SizeMB = strconv.FormatFloat(float64(size)/(1<<20), 'f', 1, 64) + " МБ"
				p.Created = tz.DateTime(created)
				data.Packages = append(data.Packages, p)
			}
		}
		rows.Close()
	}
	if rows, err := a.DB.Query(`SELECT id, hostname FROM devices WHERE COALESCE(agent_token,'')<>'' ORDER BY hostname`); err == nil {
		for rows.Next() {
			var o employeeOpt
			if rows.Scan(&o.ID, &o.Name) == nil {
				data.Devices = append(data.Devices, o)
			}
		}
		rows.Close()
	}
	if rows, err := a.DB.Query(`SELECT COALESCE(d.hostname,''), COALESCE(t.label,''),
		COALESCE(t.status,''), COALESCE(t.result,''), COALESCE(t.created_at,'')
		FROM agent_tasks t LEFT JOIN devices d ON d.id=t.device_id
		WHERE t.kind='install' ORDER BY t.id DESC LIMIT 80`); err == nil {
		for rows.Next() {
			var row deployRow
			var created string
			if rows.Scan(&row.Device, &row.Package, &row.Status, &row.Result, &created) == nil {
				row.Created = tz.DateTime(created)
				data.Recent = append(data.Recent, row)
			}
		}
		rows.Close()
	}
	data.AgentVersions = a.agentVersions()
	web.RenderPage(w, "packages", data)
}

// UploadPackage — POST /packages/upload (admin) : загрузка дистрибутива на сервер.
func (a *App) UploadPackage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Redirect(w, r, "/packages?error=Файл+слишком+большой+или+ошибка+загрузки", http.StatusSeeOther)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Redirect(w, r, "/packages?error=Не+выбран+файл", http.StatusSeeOther)
		return
	}
	defer file.Close()

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = header.Filename
	}
	args := strings.TrimSpace(r.FormValue("install_args"))
	kind := kindByExt(header.Filename)

	stored := randToken() + filepath.Ext(header.Filename)
	path := filepath.Join(packagesDir(), stored)
	dst, err := os.Create(path)
	if err != nil {
		http.Redirect(w, r, "/packages?error=Ошибка+сохранения", http.StatusSeeOther)
		return
	}
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(dst, h), file)
	// файл закрываем до проверки ошибки: иначе на Windows недописанный файл
	// не удалить, и в каталоге копился бы мусор после каждой сбойной загрузки
	closeErr := dst.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		log.Printf("загрузка дистрибутива %q: %v", header.Filename, err)
		http.Redirect(w, r, "/packages?error=Ошибка+записи", http.StatusSeeOther)
		return
	}
	a.DB.Exec(`INSERT INTO packages (name, filename, original_name, kind, size, sha256, install_args, created_by)
		VALUES (?,?,?,?,?,?,?,?)`,
		name, stored, header.Filename, kind, size, hex.EncodeToString(h.Sum(nil)), args, user.ID)
	auth.LogAction(a.DB, user.ID, "package_upload", name, kind)
	http.Redirect(w, r, "/packages?message=Дистрибутив+загружен", http.StatusSeeOther)
}

// DeletePackage — POST /packages/{id}/delete (admin).
func (a *App) DeletePackage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var fn string
	a.DB.QueryRow("SELECT COALESCE(filename,'') FROM packages WHERE id=?", id).Scan(&fn)
	if fn != "" {
		_ = os.Remove(filepath.Join(packagesDir(), fn))
	}
	a.DB.Exec("DELETE FROM packages WHERE id=?", id)
	auth.LogAction(a.DB, user.ID, "package_delete", strconv.FormatInt(id, 10), "")
	http.Redirect(w, r, "/packages?message=Дистрибутив+удалён", http.StatusSeeOther)
}

// DeployPackage — POST /packages/deploy (admin) : раздать дистрибутив на ПК.
func (a *App) DeployPackage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	pkgID, _ := strconv.ParseInt(r.FormValue("package_id"), 10, 64)
	var p installPayload
	if a.DB.QueryRow(`SELECT id, COALESCE(name,''), COALESCE(kind,''), COALESCE(filename,''), COALESCE(sha256,''), COALESCE(install_args,'')
		FROM packages WHERE id=?`, pkgID).Scan(&p.ID, &p.Name, &p.Kind, &p.Filename, &p.SHA256, &p.Args) != nil {
		http.Redirect(w, r, "/packages?error=Дистрибутив+не+найден", http.StatusSeeOther)
		return
	}
	var targets []int64
	if r.FormValue("all") != "" {
		targets = a.agentDeviceIDs()
	} else {
		for _, s := range r.Form["device"] {
			if id, err := strconv.ParseInt(s, 10, 64); err == nil {
				targets = append(targets, id)
			}
		}
	}
	if len(targets) == 0 {
		http.Redirect(w, r, "/packages?error=Не+выбраны+устройства", http.StatusSeeOther)
		return
	}
	payload, _ := json.Marshal(p)
	for _, id := range targets {
		a.enqueueTask(id, "install", string(payload), "Установка: "+p.Name, user.ID)
	}
	auth.LogAction(a.DB, user.ID, "package_deploy", p.Name, strconv.Itoa(len(targets))+" устройств")
	http.Redirect(w, r, "/packages?message=Установка+поставлена+на+"+strconv.Itoa(len(targets))+"+ПК", http.StatusSeeOther)
}

// DeployAgentUpdate — POST /packages/agent-update (admin) : разослать новую
// сборку агента на все машины с агентом.
//
// Переиспользует механизм дистрибутивов: файл agent.exe загружается как обычный
// пакет, а задача отличается видом — агент не устанавливает его, а подменяет
// себя, предварительно проверив контрольную сумму и запуск новой сборки.
func (a *App) DeployAgentUpdate(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	pkgID, _ := strconv.ParseInt(r.FormValue("package_id"), 10, 64)
	var p installPayload
	if a.DB.QueryRow(`SELECT id, COALESCE(name,''), COALESCE(kind,''), COALESCE(filename,''), COALESCE(sha256,'')
		FROM packages WHERE id=?`, pkgID).Scan(&p.ID, &p.Name, &p.Kind, &p.Filename, &p.SHA256) != nil {
		http.Redirect(w, r, "/packages?error=Сборка+не+найдена", http.StatusSeeOther)
		return
	}
	if p.Kind != "exe" {
		http.Redirect(w, r, "/packages?error=Сборка+агента+должна+быть+.exe", http.StatusSeeOther)
		return
	}
	if p.SHA256 == "" {
		http.Redirect(w, r, "/packages?error=У+сборки+нет+контрольной+суммы", http.StatusSeeOther)
		return
	}

	targets := a.agentDeviceIDs()
	if len(targets) == 0 {
		http.Redirect(w, r, "/packages?error=Нет+устройств+с+агентом", http.StatusSeeOther)
		return
	}
	payload, _ := json.Marshal(p)
	for _, id := range targets {
		a.enqueueTask(id, "selfupdate", string(payload), "Обновление агента: "+p.Name, user.ID)
	}
	auth.LogAction(a.DB, user.ID, "agent_update", p.Name, strconv.Itoa(len(targets))+" устройств")
	http.Redirect(w, r, "/packages?message=Обновление+агента+поставлено+на+"+strconv.Itoa(len(targets))+"+ПК", http.StatusSeeOther)
}

// agentVersions — сводка версий агента по парку (что уже обновилось).
func (a *App) agentVersions() []verRow {
	rows, err := a.DB.Query(`SELECT COALESCE(NULLIF(agent_version,''),'неизвестна'), COUNT(*)
		FROM devices WHERE COALESCE(agent_token,'')<>''
		GROUP BY 1 ORDER BY 2 DESC`)
	if err != nil {
		log.Printf("версии агента: %v", err)
		return nil
	}
	defer rows.Close()
	var out []verRow
	for rows.Next() {
		var v verRow
		if rows.Scan(&v.Version, &v.Count) == nil {
			out = append(out, v)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("версии агента: %v", err)
	}
	return out
}

// AgentPackageDownload — GET /api/agent-package?id=N : агент скачивает дистрибутив (по токену).
func (a *App) AgentPackageDownload(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.authAgentGet(w, r); !ok {
		return
	}
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	var fn, orig string
	if a.DB.QueryRow("SELECT COALESCE(filename,''), COALESCE(original_name,'') FROM packages WHERE id=?", id).
		Scan(&fn, &orig) != nil || fn == "" {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(packagesDir(), fn)
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	if st != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(orig)+`"`)
	_, _ = io.Copy(w, f)
}
