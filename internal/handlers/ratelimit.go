package handlers

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	maxLoginFails = 5
	loginLockDur  = 5 * time.Minute
)

type loginAttempt struct {
	fails int
	until time.Time
}

// rateLimiter — простой лимитер попыток входа по ключу (IP).
type rateLimiter struct {
	mu sync.Mutex
	m  map[string]*loginAttempt
}

func newRateLimiter() *rateLimiter { return &rateLimiter{m: map[string]*loginAttempt{}} }

// loginLimiter — лимитер веб-входа по IP; userLockout — блокировка по учётке.
var (
	loginLimiter = newRateLimiter()
	userLockout  = newRateLimiter()
)

// windowLimiter — счётчик «не больше max запросов за window» по ключу.
type windowLimiter struct {
	mu     sync.Mutex
	m      map[string]*winEntry
	max    int
	window time.Duration
}

type winEntry struct {
	count int
	reset time.Time
}

func newWindowLimiter(max int, window time.Duration) *windowLimiter {
	return &windowLimiter{m: map[string]*winEntry{}, max: max, window: window}
}

func (l *windowLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e := l.m[key]
	if e == nil || now.After(e.reset) {
		l.m[key] = &winEntry{count: 1, reset: now.Add(l.window)}
		return true
	}
	if e.count >= l.max {
		return false
	}
	e.count++
	return true
}

// agentLimiter — анти-DoS для эндпоинтов агента (по IP).
var agentLimiter = newWindowLimiter(120, time.Minute)

// helpdeskLimiter — анти-спам портала заявок (по IP): не больше 5 заявок за 10 минут.
var helpdeskLimiter = newWindowLimiter(5, 10*time.Minute)

// blockedFor возвращает остаток блокировки для ключа (0 — не заблокирован).
func (l *rateLimiter) blockedFor(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[key]
	if a == nil {
		return 0
	}
	if d := time.Until(a.until); d > 0 {
		return d
	}
	return 0
}

// fail регистрирует неудачную попытку; после maxLoginFails ставит блокировку.
func (l *rateLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[key]
	if a == nil {
		a = &loginAttempt{}
		l.m[key] = a
	}
	a.fails++
	if a.fails >= maxLoginFails {
		a.until = time.Now().Add(loginLockDur)
		a.fails = 0
	}
}

// reset снимает счётчик при успешном входе.
func (l *rateLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
