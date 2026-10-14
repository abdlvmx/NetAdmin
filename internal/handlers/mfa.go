package handlers

import (
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/edition"
	"netadmin/internal/web"
)

const mfaCookie = "mfa_challenge"

var mfaActionsLimiter = newRateLimiter()

// Cleartext is permitted only when BOTH peer and Host are loopback. Forwarded
// headers do not enable MFA; remote users need the server's actual TLS listener.
func mfaTransportAllowed(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peer := net.ParseIP(clientIP(r))
	if peer == nil || !peer.IsLoopback() {
		return false
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func setMFACookie(w http.ResponseWriter, r *http.Request, value string) {
	age := 300
	if value == "" {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: mfaCookie, Value: value, Path: "/login", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: age})
}

func challengeCookie(r *http.Request) string {
	c, err := r.Cookie(mfaCookie)
	if err != nil || len(c.Value) != 64 {
		return ""
	}
	return c.Value
}

func (a *App) clearMFAChallenge(w http.ResponseWriter, r *http.Request) {
	if token := challengeCookie(r); token != "" {
		a.mfa().ForgetChallenge(token)
	}
	setMFACookie(w, r, "")
}

func (a *App) loginDestination(id int64) string {
	var role string
	if edition.Events && a.DB.QueryRow("SELECT role FROM users WHERE id=?", id).Scan(&role) == nil && role == "analyst" {
		return "/events"
	}
	return "/dashboard"
}

func mfaError(err error) string {
	switch {
	case errors.Is(err, auth.ErrMFACode):
		return "Код неверен или уже использован. Дождитесь нового кода либо используйте резервный."
	case errors.Is(err, auth.ErrMFALocked):
		return "Слишком много неверных кодов. Повторите через 5 минут."
	case errors.Is(err, auth.ErrMFAExpired), errors.Is(err, auth.ErrMFAState):
		return "Время подтверждения истекло или настройки изменились. Начните заново."
	default:
		return "Двухфакторная проверка недоступна. Повторите позже или обратитесь к администратору сервера."
	}
}

func (a *App) renderMFALogin(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Cache-Control", "no-store")
	if !mfaTransportAllowed(r) {
		http.Error(w, "Для двухфакторного входа нужен HTTPS.", http.StatusForbidden)
		return
	}
	_, name, err := a.mfa().Challenge(challengeCookie(r))
	if err != nil {
		a.clearMFAChallenge(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	web.Render(w, "login.html", map[string]any{"MFA": true, "Username": name, "Error": message, "CSRF": csrfToken(r)})
}

func (a *App) MFALoginPage(w http.ResponseWriter, r *http.Request) { a.renderMFALogin(w, r, "") }

func (a *App) MFALogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !mfaTransportAllowed(r) {
		http.Error(w, "Для двухфакторного входа нужен HTTPS.", http.StatusForbidden)
		return
	}
	ip := clientIP(r)
	_, name, err := a.mfa().Challenge(challengeCookie(r))
	if err != nil {
		a.clearMFAChallenge(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if loginLimiter.blockedFor(ip) > 0 || userLockout.blockedFor(name) > 0 {
		a.renderMFALogin(w, r, "Слишком много попыток входа. Повторите через 5 минут.")
		return
	}
	id, name, session, err := a.mfa().FinishChallenge(challengeCookie(r), r.FormValue("code"))
	if err != nil {
		if errors.Is(err, auth.ErrMFACode) || errors.Is(err, auth.ErrMFALocked) {
			loginLimiter.fail(ip)
			userLockout.fail(name)
			auth.LogAction(a.DB, id, "login_mfa_failed", name, ip)
		} else if !errors.Is(err, auth.ErrMFAExpired) && !errors.Is(err, auth.ErrMFAState) {
			log.Printf("MFA login unavailable: %v", err)
		}
		a.renderMFALogin(w, r, mfaError(err))
		return
	}
	loginLimiter.reset(ip)
	userLockout.reset(name)
	setMFACookie(w, r, "")
	setSessionCookie(w, session, r)
	auth.LogAction(a.DB, id, "login_mfa", name, ip)
	http.Redirect(w, r, a.loginDestination(id), http.StatusSeeOther)
}

func sessionCookieValue(r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return c.Value
}

func (a *App) renderProfile(w http.ResponseWriter, r *http.Request, data profileData) {
	w.Header().Set("Cache-Control", "no-store")
	data.MFATransport = mfaTransportAllowed(r)
	data.CSRF = csrfToken(r)
	state, err := a.mfa().Status(data.User.ID, sessionCookieValue(r))
	if err != nil {
		data.MFAUnavailable = true
		log.Printf("MFA settings unavailable: %v", err)
	}
	// Never expose a provisioning secret over cleartext LAN HTTP.
	if !data.MFATransport {
		state.SetupSecret = ""
	}
	data.MFA = state
	a.profileAccess(r, &data)
	web.RenderPage(w, "profile", data)
}

func (a *App) MFAAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if a.Demo {
		http.Error(w, "Двухфакторный вход не настраивается в демо.", http.StatusForbidden)
		return
	}
	if !mfaTransportAllowed(r) {
		http.Error(w, "Откройте профиль по HTTPS для настройки двухфакторного входа.", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Неверная форма", http.StatusBadRequest)
		return
	}
	operation := r.PathValue("operation")
	if operation != "begin" && operation != "enable" && operation != "cancel" && operation != "disable" && operation != "recovery" {
		http.NotFound(w, r)
		return
	}
	key := strconv.FormatInt(user.ID, 10)
	if mfaActionsLimiter.blockedFor(key) > 0 {
		http.Error(w, "Слишком много попыток. Повторите через 5 минут.", http.StatusTooManyRequests)
		return
	}
	passwordHash := ""
	if operation == "begin" || operation == "disable" || operation == "recovery" {
		err := a.DB.QueryRow("SELECT password_hash FROM users WHERE id=? AND is_active=1", user.ID).Scan(&passwordHash)
		if err != nil {
			http.Error(w, "Проверка учётной записи недоступна.", http.StatusServiceUnavailable)
			return
		}
		if !auth.VerifyPassword(r.FormValue("password"), passwordHash) {
			mfaActionsLimiter.fail(key)
			auth.LogAction(a.DB, user.ID, "mfa_password_failed", user.Username, "")
			http.Redirect(w, r, "/profile?error=bad_current_password", http.StatusSeeOther)
			return
		}
	}
	var result auth.MFAResult
	var err error
	switch operation {
	case "begin":
		err = a.mfa().BeginSetup(user.ID, sessionCookieValue(r), passwordHash)
	case "cancel":
		err = a.mfa().CancelSetup(user.ID, sessionCookieValue(r))
	case "enable":
		result, err = a.mfa().Enable(user.ID, sessionCookieValue(r), r.FormValue("code"))
	case "disable", "recovery":
		result, err = a.mfa().Change(user.ID, passwordHash, r.FormValue("code"), operation == "disable")
	}
	if err != nil {
		if errors.Is(err, auth.ErrMFACode) || errors.Is(err, auth.ErrMFALocked) {
			mfaActionsLimiter.fail(key)
			auth.LogAction(a.DB, user.ID, "mfa_code_failed", user.Username, operation)
		} else if !errors.Is(err, auth.ErrMFAState) && !errors.Is(err, auth.ErrMFAExpired) {
			log.Printf("MFA %s unavailable: %v", operation, err)
		}
		http.Redirect(w, r, "/profile?error="+url.QueryEscape(mfaError(err)), http.StatusSeeOther)
		return
	}
	mfaActionsLimiter.reset(key)
	auth.LogAction(a.DB, user.ID, "mfa_"+operation, user.Username, "")
	if result.Session != "" {
		setSessionCookie(w, result.Session, r)
		// Status rendering must use the new session after the atomic revocation.
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		clone.Header.Set("Cookie", "session="+result.Session)
		r = clone
	}
	if len(result.RecoveryCodes) > 0 {
		a.renderProfile(w, r, profileData{User: user, Active: "profile", Message: "mfa_codes", RecoveryCodes: result.RecoveryCodes})
		return
	}
	http.Redirect(w, r, "/profile?message=mfa_"+operation, http.StatusSeeOther)
}
