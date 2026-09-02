// Package notify — email-уведомления (SMTP) о важных событиях.
package notify

import (
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net/smtp"
	"strings"

	"netadmin/internal/config"
)

// Message шлёт произвольное уведомление на email (асинхронно).
// Если SMTP не настроен — тихо ничего не делает.
func Message(text string) {
	sendAsync("NetAdmin — уведомление", text)
}

// CriticalEvent шлёт уведомление о критическом событии/инциденте.
func CriticalEvent(hostname, message string) {
	host := hostname
	if host == "" {
		host = "—"
	}
	sendAsync("NetAdmin — важное событие: "+host, "Хост: "+host+"\n\n"+message)
}

// Email шлёт письмо конкретному адресату (например, заявителю helpdesk), асинхронно.
// Если SMTP не настроен или адрес пуст — тихо ничего не делает.
func Email(to, subject, body string) {
	cfg := config.Load()
	// адрес заявителя приходит из публичной формы — проверяем его отдельно
	to = strings.TrimSpace(to)
	if cfg.SMTPHost == "" || !validAddr(cfg.SMTPFrom) || !validAddr(to) {
		return
	}
	go func() {
		if err := sendMailTo(cfg, []string{to}, subject, body); err != nil {
			fmt.Println("notify email error:", err)
		}
	}()
}

// SendTest отправляет тестовое письмо синхронно (для кнопки проверки).
func SendTest() error {
	cfg := config.Load()
	if !smtpConfigured(cfg) {
		return errors.New("SMTP не настроен")
	}
	return sendMail(cfg, "NetAdmin — тестовое уведомление", "Канал email-уведомлений работает.")
}

func sendAsync(subject, body string) {
	cfg := config.Load()
	if !smtpConfigured(cfg) {
		return
	}
	go func() {
		if err := sendMail(cfg, subject, body); err != nil {
			fmt.Println("notify email error:", err)
		}
	}()
}

func smtpConfigured(cfg config.Config) bool {
	return cfg.SMTPHost != "" && cfg.SMTPFrom != "" && strings.TrimSpace(cfg.SMTPTo) != ""
}

// validAddr отсеивает адреса с управляющими символами и пробелами. Такой адрес
// попадает и в заголовок письма, и в SMTP-команду RCPT: перевод строки внутри
// него позволяет дописать собственные заголовки или команды.
func validAddr(s string) bool {
	if s == "" || len(s) > 320 {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r == 0x7f || r == ',' || r == ';' || r == '<' || r == '>' {
			return false
		}
	}
	return strings.Count(s, "@") == 1
}

// recipients разбирает список получателей (через запятую/точку с запятой/пробел).
func recipients(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' })
	var out []string
	for _, x := range f {
		if x = strings.TrimSpace(x); validAddr(x) {
			out = append(out, x)
		}
	}
	return out
}

func buildMessage(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.BEncoding.Encode("UTF-8", subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// sendMail отправляет письмо настроенным получателям (cfg.SMTPTo).
func sendMail(cfg config.Config, subject, body string) error {
	return sendMailTo(cfg, recipients(cfg.SMTPTo), subject, body)
}

// sendMailTo отправляет письмо заданным получателям: порт 465 — неявный TLS,
// иначе STARTTLS (если поддержан сервером).
func sendMailTo(cfg config.Config, to []string, subject, body string) error {
	if cfg.SMTPHost == "" || !validAddr(cfg.SMTPFrom) || len(to) == 0 {
		return errors.New("SMTP не настроен")
	}
	for _, r := range to {
		if !validAddr(r) {
			return errors.New("некорректный адрес получателя")
		}
	}
	port := cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, port)
	msg := buildMessage(cfg.SMTPFrom, to, subject, body)

	var auth smtp.Auth
	if cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	}

	if port == 465 {
		return sendImplicitTLS(addr, cfg.SMTPHost, auth, cfg.SMTPFrom, to, msg)
	}
	// smtp.SendMail сам выполняет STARTTLS, если сервер его предлагает.
	return smtp.SendMail(addr, auth, cfg.SMTPFrom, to, msg)
}

func sendImplicitTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}
