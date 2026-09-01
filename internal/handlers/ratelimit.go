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
	seen  time.Time // когда ключ трогали последний раз — для вытеснения
}

// Ключи лимитеров приходят извне: IP клиента и введённый логин. Без вытеснения
// карты растут неограниченно и сами становятся способом исчерпать память.
const (
	maxLimiterKeys = 10000
	limiterTTL     = 30 * time.Minute // заведомо больше срока блокировки
)

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
	if len(l.m) >= maxLimiterKeys {
		l.m = make(map[string]*winEntry, maxLimiterKeys/2)
	} else {
		for k, e := range l.m {
			if now.After(e.reset) {
				delete(l.m, k)
			}
		}
	}
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

// trackLimiter — анти-перебор кодов заявок на странице отслеживания (по IP).
// Код заявки — единственное, что защищает чужое обращение от просмотра.
var trackLimiter = newWindowLimiter(30, 10*time.Minute)

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
	now := time.Now()
	l.evict(now)
	a := l.m[key]
	if a == nil {
		a = &loginAttempt{}
		l.m[key] = a
	}
	a.seen = now
	a.fails++
	if a.fails >= maxLoginFails {
		a.until = now.Add(loginLockDur)
		a.fails = 0
	}
}

// evict убирает давно не встречавшиеся ключи. Вызывается под уже взятым мьютексом.
//
// Полный сброс при переполнении снял бы и действующие блокировки, но добраться
// до потолка непросто: неудачные попытки с одного адреса упираются в блокировку
// по IP, а доступ к серверу и так ограничен разрешёнными подсетями.
func (l *rateLimiter) evict(now time.Time) {
	if len(l.m) >= maxLimiterKeys {
		l.m = make(map[string]*loginAttempt, maxLimiterKeys/2)
		return
	}
	for k, a := range l.m {
		if now.Sub(a.seen) > limiterTTL && a.until.Before(now) {
			delete(l.m, k)
		}
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
