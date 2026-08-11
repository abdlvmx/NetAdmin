package notify

import (
	"strings"
	"testing"

	"netadmin/internal/config"
)

func TestRecipients(t *testing.T) {
	got := recipients("admin@x.ru, it@y.ru; ops@z.ru\nboss@w.ru")
	if len(got) != 4 {
		t.Fatalf("ожидалось 4 получателя, получено %d (%v)", len(got), got)
	}
	if recipients("  ") != nil {
		t.Fatal("пустая строка должна давать nil")
	}
}

func TestBuildMessage(t *testing.T) {
	msg := string(buildMessage("from@x.ru", []string{"a@y.ru", "b@z.ru"}, "Тест кириллица", "тело письма"))
	if !strings.Contains(msg, "To: a@y.ru, b@z.ru\r\n") {
		t.Fatal("нет заголовка To со всеми получателями")
	}
	if !strings.Contains(msg, "=?UTF-8?b?") && !strings.Contains(msg, "=?UTF-8?B?") {
		t.Fatalf("тема не закодирована для кириллицы: %q", msg)
	}
	if !strings.Contains(msg, "Content-Type: text/plain; charset=UTF-8") {
		t.Fatal("нет UTF-8 Content-Type")
	}
	if !strings.HasSuffix(msg, "тело письма") {
		t.Fatal("нет тела письма")
	}
}

func TestSmtpConfigured(t *testing.T) {
	if smtpConfigured(config.Config{}) {
		t.Fatal("пустой конфиг не настроен")
	}
	if !smtpConfigured(config.Config{SMTPHost: "smtp.x.ru", SMTPFrom: "a@x.ru", SMTPTo: "b@y.ru"}) {
		t.Fatal("заполненный конфиг должен считаться настроенным")
	}
}
