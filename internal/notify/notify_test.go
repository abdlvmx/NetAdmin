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

// Адрес с переводом строки позволил бы дописать заголовки письма и SMTP-команды.
func TestValidAddrRejectsInjection(t *testing.T) {
	bad := []string{
		"a@b.ru\r\nBcc: victim@x.ru",
		"a@b.ru\nX-Injected: 1",
		"a@b.ru someone@else.ru",
		"<a@b.ru>",
		"a@b.ru,c@d.ru",
		"без-собаки.ru",
		"два@собаки@ru",
		"",
	}
	for _, s := range bad {
		if validAddr(s) {
			t.Errorf("%q должен отвергаться", s)
		}
	}
	for _, s := range []string{"user@example.ru", "it-otdel@firma.local"} {
		if !validAddr(s) {
			t.Errorf("%q должен приниматься", s)
		}
	}
}

// В списке получателей мусорные адреса отсеиваются, годные остаются.
func TestRecipientsFiltersInvalid(t *testing.T) {
	got := recipients("ok@a.ru, плохой адрес, second@b.ru")
	if len(got) != 2 || got[0] != "ok@a.ru" || got[1] != "second@b.ru" {
		t.Fatalf("ожидались два годных адреса, получено %v", got)
	}
}
