//go:build securityevents

package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/securityevents"
)

func (a *App) registerEventsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /events", a.SecurityEventsPage)
	mux.HandleFunc("POST /events/devices/{id}/policy", a.SetSecurityEventsPolicy)
	mux.HandleFunc("POST /api/agent-events/poll", a.AgentEventsPoll)
	mux.HandleFunc("POST /api/agent-events/batch", a.AgentEventsBatch)
	mux.HandleFunc("GET /events/findings/{id}", a.SecurityFindingPage)
	mux.HandleFunc("POST /events/findings/{id}", a.UpdateSecurityFinding)
	mux.HandleFunc("POST /events/rules/{id}", a.UpdateSecurityRule)
	mux.HandleFunc("POST /events/rules/{id}/exceptions", a.AddSecurityException)
	mux.HandleFunc("POST /events/exceptions/{id}/delete", a.DeleteSecurityException)
	mux.HandleFunc("POST /events/backups/{operation}", a.EventsBackupAction)
}

// Events requires a native HTTPS connection; forwarded headers never enable it.
func eventsNativeTLSConfigured(r *http.Request) bool {
	if r.TLS == nil {
		return false
	}
	s, err := config.Load().TLSSettingsAt(config.DataDir(), true)
	return err == nil && s.Enabled()
}

func eventsHasCapability(raw string) bool {
	var caps []string
	if json.Unmarshal([]byte(raw), &caps) != nil {
		return false
	}
	for _, c := range caps {
		if c == securityevents.Capability {
			return true
		}
	}
	return false
}

type eventsDevice struct {
	ID                        int64
	Hostname, IP, Token, Caps string
	DeviceType, OS, Vendor    string
	Ports                     string
}

func (d eventsDevice) isPC() bool {
	return inferDeviceType(d.DeviceType, d.OS, d.Vendor, d.Hostname, d.Ports) == "pc"
}

func (a *App) eventsDevice(r *http.Request, id int64) (eventsDevice, error) {
	d := eventsDevice{ID: id}
	err := a.DB.QueryRowContext(r.Context(), `SELECT hostname,COALESCE(ip_address,''),COALESCE(agent_token,''),
		COALESCE(agent_capabilities,''),COALESCE(device_type,''),COALESCE(os_type,''),COALESCE(manufacturer,''),COALESCE(open_ports,'')
		FROM devices WHERE id=?`, id).Scan(&d.Hostname, &d.IP, &d.Token, &d.Caps, &d.DeviceType, &d.OS, &d.Vendor, &d.Ports)
	return d, err
}

// SetSecurityEventsPolicy records consent for this device's current registration.
// Changing the agent token invalidates the consent in the separate Events store.
func (a *App) SetSecurityEventsPolicy(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if a.Demo {
		http.Error(w, "Events недоступен в демонстрационном режиме", http.StatusForbidden)
		return
	}
	if a.Events == nil {
		http.Error(w, "Events unavailable", http.StatusServiceUnavailable)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid device", http.StatusBadRequest)
		return
	}
	if err = r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	enabled := r.FormValue("enabled") == "1"
	profile := r.FormValue("profile")
	if profile == "" && !enabled {
		profile = "system"
	}
	if profile != "system" && profile != "security" {
		http.Error(w, "invalid profile", http.StatusBadRequest)
		return
	}
	d, err := a.eventsDevice(r, id)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "device unavailable", http.StatusServiceUnavailable)
		return
	}
	if enabled {
		if !eventsNativeTLSConfigured(r) {
			http.Error(w, "Для Events настройте HTTPS сервера и откройте панель по HTTPS", http.StatusForbidden)
			return
		}
		if !d.isPC() || d.Token == "" || !eventsHasCapability(d.Caps) {
			http.Error(w, "Events requires an enrolled PC supporting security_events_v1", http.StatusConflict)
			return
		}
		if r.FormValue("consent") != "1" || (profile == "security" && r.FormValue("security_privacy") != "1") {
			http.Error(w, "Подтвердите сбор событий и обработку персональных данных Security", http.StatusBadRequest)
			return
		}
	}
	if _, err = a.Events.SetPolicy(r.Context(), id, d.Token, enabled, profile); err != nil {
		log.Printf("Events policy: %v", err)
		http.Error(w, "policy not saved", http.StatusServiceUnavailable)
		return
	}
	auth.LogAction(a.DB, user.ID, "events_policy", d.Hostname,
		fmt.Sprintf("device_id=%d enabled=%t profile=%s consent=%t security_privacy=%t", id, enabled, profile,
			r.FormValue("consent") == "1", r.FormValue("security_privacy") == "1"))
	http.Redirect(w, r, "/events?tab=collection&message=Настройки+Events+сохранены", http.StatusSeeOther)
}

func (a *App) eventsAgent(w http.ResponseWriter, r *http.Request, limit int64) (agentReq, bool) {
	if r.TLS == nil {
		http.Error(w, "native HTTPS required", http.StatusForbidden)
		return agentReq{}, false
	}
	if a.Demo {
		http.Error(w, "Events disabled in demo", http.StatusForbidden)
		return agentReq{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	ag, ok := a.authAgentPost(w, r)
	if !ok {
		return agentReq{}, false
	}
	if ag.Enroll || ag.DeviceID <= 0 {
		http.Error(w, "enrolled device required", http.StatusForbidden)
		return agentReq{}, false
	}
	if a.Events == nil {
		http.Error(w, "Events unavailable", http.StatusServiceUnavailable)
		return agentReq{}, false
	}
	return ag, true
}

// AgentEventsPoll accepts capabilities/status at the top level with the shared
// timestamp/nonce envelope, and signs the {policy: ...} response.
func (a *App) AgentEventsPoll(w http.ResponseWriter, r *http.Request) {
	ag, ok := a.eventsAgent(w, r, 16<<10)
	if !ok {
		return
	}
	var p securityevents.PollRequest
	if json.Unmarshal(ag.Body, &p) != nil || len(p.Capabilities) > 32 {
		http.Error(w, "bad poll", http.StatusBadRequest)
		return
	}
	for _, c := range p.Capabilities {
		if len(c) > 64 || strings.TrimSpace(c) == "" {
			http.Error(w, "bad capabilities", http.StatusBadRequest)
			return
		}
	}
	d, err := a.eventsDevice(r, ag.DeviceID)
	if err != nil {
		http.Error(w, "device unavailable", http.StatusServiceUnavailable)
		return
	}
	if d.Token != ag.Key {
		http.Error(w, "agent registration changed", http.StatusUnauthorized)
		return
	}
	caps, _ := json.Marshal(p.Capabilities)
	if _, err = a.DB.ExecContext(r.Context(), `UPDATE devices SET agent_capabilities=? WHERE id=? AND agent_token=?`, string(caps), ag.DeviceID, ag.Key); err != nil {
		http.Error(w, "capabilities not saved", http.StatusServiceUnavailable)
		return
	}
	policy, err := a.Events.Policy(r.Context(), ag.DeviceID, ag.Key)
	if err != nil {
		http.Error(w, "policy unavailable", http.StatusServiceUnavailable)
		return
	}
	if !d.isPC() || !eventsHasCapability(string(caps)) {
		if policy.Enabled {
			policy, err = a.Events.SetPolicy(r.Context(), ag.DeviceID, ag.Key, false, policy.Profile)
			if err != nil {
				http.Error(w, "policy not saved", http.StatusServiceUnavailable)
				return
			}
			auth.LogAction(a.DB, 0, "events_policy", d.Hostname, "Сбор автоматически выключен: ПК или агент перестал поддерживать Events; требуется новое согласие администратора")
		}
	}
	if err = a.Events.UpdateStatus(r.Context(), ag.DeviceID, ag.Key, p.Status); err != nil {
		if errors.Is(err, securityevents.ErrInvalid) {
			http.Error(w, "invalid status", http.StatusBadRequest)
		} else {
			http.Error(w, "status not saved", http.StatusServiceUnavailable)
		}
		return
	}
	writeAgentJSON(w, ag.Key, securityevents.PollResponse{Policy: policy})
}

// AgentEventsBatch acknowledges only a successfully committed, validated batch.
// Retries use a fresh nonce and the same batch ID; the store deduplicates them.
func (a *App) AgentEventsBatch(w http.ResponseWriter, r *http.Request) {
	ag, ok := a.eventsAgent(w, r, securityevents.MaxBatchBytes)
	if !ok {
		return
	}
	var p struct {
		Batch securityevents.Batch `json:"batch"`
	}
	if json.Unmarshal(ag.Body, &p) != nil {
		http.Error(w, "bad batch", http.StatusBadRequest)
		return
	}
	d, err := a.eventsDevice(r, ag.DeviceID)
	if err != nil {
		http.Error(w, "device unavailable", http.StatusServiceUnavailable)
		return
	}
	if d.Token != ag.Key {
		http.Error(w, "agent registration changed", http.StatusUnauthorized)
		return
	}
	if !d.isPC() || !eventsHasCapability(d.Caps) {
		http.Error(w, "unsupported device", http.StatusForbidden)
		return
	}
	if err = a.Events.AcceptBatch(r.Context(), ag.DeviceID, ag.Key, p.Batch); err != nil {
		switch {
		case errors.Is(err, securityevents.ErrInvalid):
			http.Error(w, "invalid batch", http.StatusBadRequest)
		case errors.Is(err, securityevents.ErrDisabled):
			http.Error(w, "Events disabled", http.StatusForbidden)
		case errors.Is(err, securityevents.ErrGeneration), errors.Is(err, securityevents.ErrBatchConflict), errors.Is(err, securityevents.ErrEventConflict):
			http.Error(w, "batch conflicts with current policy or saved data", http.StatusConflict)
		default:
			log.Printf("Events batch: %v", err)
			http.Error(w, "batch not committed", http.StatusServiceUnavailable)
		}
		return
	}
	writeAgentJSON(w, ag.Key, map[string]bool{"ok": true})
}
