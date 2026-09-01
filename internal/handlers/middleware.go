package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
)

const csrfCookie = "csrf"

// withRecover перехватывает панику в обработчике. Без него net/http гасит
// панику молча, обрывая соединение: пользователь видит пустую страницу,
// а в журнале не остаётся ни строчки — искать такой сбой потом нечем.
func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			// служебный сигнал net/http для намеренного обрыва — пропускаем дальше
			if v == http.ErrAbortHandler {
				panic(v)
			}
			log.Printf("паника при обработке %s %s: %v\n%s", r.Method, r.URL.Path, v, debug.Stack())
			http.Error(w, "внутренняя ошибка сервера", http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	// всё своё (go:embed), внешних ресурсов нет; inline нужен для наших стилей/скриптов
	h.Set("Content-Security-Policy",
		"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
			"script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
}

// ensureCSRF возвращает CSRF-токен из cookie, создавая его при отсутствии.
func ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && c.Value != "" {
		return c.Value
	}
	tok := randToken()
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: tok, Path: "/",
		SameSite: http.SameSiteLaxMode,
	})
	return tok
}

// csrfExempt — пути без CSRF-проверки: приём от агента (авторизация токеном,
// без cookie) и вход/первичная настройка (сессии ещё нет).
func csrfExempt(path string) bool {
	return strings.HasPrefix(path, "/api/agent-") || path == "/login" || path == "/setup"
}

// withSecurity оборачивает роутер: ограничение по подсетям, security-заголовки
// и CSRF (double-submit).
func (a *App) withSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)

		// Канал не шифруется, поэтому доступ ограничен разрешёнными подсетями.
		// Проверка идёт до всего остального: обращение из чужой сети не должно
		// доходить ни до аутентификации, ни до публичного портала заявок.
		if !a.Allow.Allows(clientIP(r)) {
			http.Error(w, "доступ из этой сети запрещён", http.StatusForbidden)
			return
		}

		// ограничение размера тела запроса (анти-DoS)
		bodyLimit := int64(1 << 20) // 1 МБ по умолчанию
		if r.URL.Path == "/packages/upload" {
			bodyLimit = 1 << 30 // 1 ГБ — загрузка дистрибутивов ПО
		}
		r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)

		// анти-DoS на эндпоинтах агента (по IP)
		if strings.HasPrefix(r.URL.Path, "/api/agent-") && !agentLimiter.allow(clientIP(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

		cookieTok := ensureCSRF(w, r)

		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if !csrfExempt(r.URL.Path) {
				sent := r.Header.Get("X-CSRF-Token")
				if sent == "" {
					sent = r.FormValue("csrf_token")
				}
				if sent == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(cookieTok)) != 1 {
					http.Error(w, "CSRF token invalid", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
