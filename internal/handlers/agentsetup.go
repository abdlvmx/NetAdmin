package handlers

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"netadmin/internal/agentcfg"
	"netadmin/internal/auth"
	"netadmin/internal/config"
)

// Готовый установщик агента: тот же agent.exe, но с уже вписанными адресом
// сервера и кодом регистрации (см. internal/agentcfg).
//
// Это самый короткий путь установки из всех, что есть на странице настроек.
// Файл кладут на сетевую папку или флешку, обходят машины и запускают двойным
// щелчком: агент видит настройки внутри себя, ничего не спрашивает и просит
// только подтвердить установку и права. Ни консоли, ни политик PowerShell, ни
// сорокатрёхзначного кода, который надо откуда-то скопировать.

// AgentSetupExe — GET /settings/agent-setup.exe (admin).
//
// Вписывает постоянный токен: этот файл живёт на общей папке долго, и
// одноразовый код на нём протух бы через час. Для точечной установки есть
// вариант с кодом — он ниже.
func (a *App) AgentSetupExe(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cfg := config.Load()
	if strings.TrimSpace(cfg.AgentToken) == "" {
		http.Redirect(w, r, "/settings?message=no_agent_token", http.StatusSeeOther)
		return
	}
	a.serveAgentSetup(w, r, user, cfg.AgentToken, "постоянный токен")
}

// EnrollCodeInstaller — GET /settings/enroll-code/{id}/installer (admin):
// установщик с одноразовым кодом внутри.
//
// Код тот же, что показан рядом строкой для PowerShell, — со своим сроком и
// числом установок. Отозвав его, администратор отзывает и разошедшиеся копии
// файла: сам файл ничего не значит без действующего кода.
func (a *App) EnrollCodeInstaller(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var code string
	err := a.DB.QueryRow(`SELECT code FROM enroll_codes
		WHERE id=? AND revoked=0 AND expires_at > datetime('now')
		  AND (max_uses=0 OR used_count < max_uses)`, r.PathValue("id")).Scan(&code)
	if err == sql.ErrNoRows {
		http.Redirect(w, r, "/settings?error=Код+больше+не+действует", http.StatusSeeOther)
		return
	}
	if err != nil {
		http.Error(w, "не удалось прочитать код: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.serveAgentSetup(w, r, user, code, "одноразовый код")
}

// serveAgentSetup собирает и отдаёт файл. kind попадает в журнал действий:
// какой ключ уехал в разошедшийся по офису файл — вопрос, который однажды
// зададут.
func (a *App) serveAgentSetup(w http.ResponseWriter, r *http.Request, user *auth.User, token, kind string) {
	exe, ok := a.agentBytes()
	if !ok {
		http.Error(w, "сборка агента недоступна: этот сервер собран без встроенного "+
			"агента — загрузите agent.exe в разделе «Установка ПО»", http.StatusNotFound)
		return
	}
	out, err := agentcfg.Append(exe, agentcfg.Settings{
		ServerURL: agentServerURL(r),
		Token:     token,
	})
	if err != nil {
		http.Error(w, "не удалось собрать установщик: "+err.Error(),
			http.StatusInternalServerError)
		return
	}

	auth.LogAction(a.DB, user.ID, "download_agent_setup", "settings", kind)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="netadmin-agent-setup.exe"`)
	// Содержимое своё у каждой выдачи (адрес, код), поэтому ServeContent с его
	// проверками кэша здесь не к месту: файл собирается заново каждый раз.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(out)
}

// agentBytes — сборка агента, которую сервер раздаёт сейчас: встроенная либо
// загруженная в «Установку ПО». Тот же выбор, что делает /agent.exe.
func (a *App) agentBytes() ([]byte, bool) {
	b, ok := a.latestAgentBuild()
	if !ok {
		return nil, false
	}
	if b.Embedded {
		data, _, ok := agentEmbedded()
		return data, ok
	}
	data, err := os.ReadFile(filepath.Join(packagesDir(), b.Stored))
	if err != nil {
		return nil, false
	}
	return data, true
}

// enrolledAgents — сколько машин уже с агентом и какая пришла последней.
type enrolledAgents struct {
	Count int         `json:"count"`
	Last  *agentDebut `json:"last,omitempty"`
}

// agentDebut — машина, зарегистрировавшаяся последней.
type agentDebut struct {
	ID       int64  `json:"id"`
	Hostname string `json:"hostname"`
}

// EnrolledAgents — GET /api/agents/enrolled (admin).
//
// Нужен странице настроек, чтобы сказать «подключился», не заставляя человека
// уходить в список устройств и обновлять его. Установка агента на чужой машине
// заканчивается тем, что там закрывается окно, — а состоялась она или нет,
// видно только на сервере, и до сих пор это надо было идти проверять самому.
func (a *App) EnrolledAgents(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var out enrolledAgents
	_ = a.DB.QueryRow(
		"SELECT COUNT(*) FROM devices WHERE COALESCE(agent_token,'')<>''").Scan(&out.Count)

	var d agentDebut
	err := a.DB.QueryRow(`SELECT id, hostname FROM devices
		WHERE COALESCE(agent_token,'')<>'' ORDER BY id DESC LIMIT 1`).
		Scan(&d.ID, &d.Hostname)
	if err == nil {
		out.Last = &d
	}
	writeJSON(w, out)
}

// localAgentInstalled — стоит ли агент на самой машине сервера.
//
// Сверяем по имени: устройство с агентом и тем же именем, что у сервера. Имя
// может прийти полным (с доменной частью), поэтому сравнивается короткое и без
// оглядки на регистр. Способ не идеальный, но честный: он опирается на то, что
// сервер действительно видит, а не на отметку «кнопку нажимали».
func (a *App) localAgentInstalled() bool {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return false
	}
	short := strings.ToLower(strings.SplitN(host, ".", 2)[0])
	var n int
	_ = a.DB.QueryRow(`SELECT COUNT(*) FROM devices
		WHERE COALESCE(agent_token,'')<>''
		  AND LOWER(CASE WHEN INSTR(hostname,'.')>0
		            THEN SUBSTR(hostname,1,INSTR(hostname,'.')-1) ELSE hostname END)=?`,
		short).Scan(&n)
	return n > 0
}

// agentsTotal — сколько устройств уже с агентом.
func (a *App) agentsTotal() int {
	var n int
	_ = a.DB.QueryRow(
		"SELECT COUNT(*) FROM devices WHERE COALESCE(agent_token,'')<>''").Scan(&n)
	return n
}
