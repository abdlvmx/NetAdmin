// Package monitor — активные проверки доступности сервисов (HTTP/TCP/DNS/…).
package monitor

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

// Result — итог одной проверки.
type Result struct {
	Up        bool
	LatencyMs int
	Detail    string
}

var httpClient = &http.Client{
	Timeout:       8 * time.Second,
	Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// defaultPorts — порт по умолчанию для типов без явного порта.
var defaultPorts = map[string]string{"rdp": "3389", "smtp": "25", "imap": "143", "tcp": ""}

// Check выполняет проверку указанного типа и возвращает доступность и задержку.
func Check(typ, target string) Result {
	typ = strings.ToLower(strings.TrimSpace(typ))
	target = strings.TrimSpace(target)
	start := time.Now()
	switch typ {
	case "http", "https":
		return checkHTTP(typ, target, start)
	case "dns":
		_, err := net.LookupHost(target)
		return done(start, err == nil, errText(err))
	default: // tcp, rdp, smtp, imap — TCP-коннект
		addr := target
		if !strings.Contains(addr, ":") {
			if p := defaultPorts[typ]; p != "" {
				addr = addr + ":" + p
			}
		}
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			conn.Close()
		}
		return done(start, err == nil, errText(err))
	}
}

func checkHTTP(typ, target string, start time.Time) Result {
	url := target
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = typ + "://" + target
	}
	resp, err := httpClient.Get(url)
	if err != nil {
		return done(start, false, errText(err))
	}
	defer resp.Body.Close()
	up := resp.StatusCode < 400
	return done(start, up, resp.Status)
}

func done(start time.Time, up bool, detail string) Result {
	return Result{Up: up, LatencyMs: int(time.Since(start).Milliseconds()), Detail: detail}
}

func errText(err error) string {
	if err == nil {
		return "OK"
	}
	return err.Error()
}
