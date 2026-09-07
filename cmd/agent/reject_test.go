package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

// captureLog перехватывает журнал агента на время теста.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return &buf
}

func freshRejects(t *testing.T) {
	t.Helper()
	prev := rejects
	rejects = &rejectLog{seen: map[string]time.Time{}}
	t.Cleanup(func() { rejects = prev })
}

// TestRejectHintExplainsTokenMismatch — ради этого всё и затевалось: «bad
// signature» само по себе не говорит человеку ничего, а причина у него всегда
// одна и та же.
func TestRejectHintExplainsTokenMismatch(t *testing.T) {
	hint := rejectHint(403, "bad signature")
	if hint == "" {
		t.Fatal("для 403 bad signature подсказки нет")
	}
	for _, want := range []string{"токен", "-check"} {
		if !strings.Contains(strings.ToLower(hint), strings.ToLower(want)) {
			t.Errorf("в подсказке нет %q:\n%s", want, hint)
		}
	}
}

// TestRejectHintByStatus — остальные ответы сервера тоже должны объясняться,
// а неизвестный код не выдумывать причину.
func TestRejectHintByStatus(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   bool
	}{
		{403, "bad signature", true},
		{401, "unauthorized", true},
		{409, "already registered", true},
		{429, "too many requests", true},
		{500, "internal error", true},
		{418, "нечто своё", false},
	}
	for _, c := range cases {
		got := rejectHint(c.status, c.body) != ""
		if got != c.want {
			t.Errorf("HTTP %d: подсказка=%v, ожидалось %v", c.status, got, c.want)
		}
	}
}

// TestRejectRepeatIsThrottled — шесть отправок за круг спотыкаются об одну и ту
// же причину, и раньше журнал получал шесть одинаковых строк каждые 15 секунд.
func TestRejectRepeatIsThrottled(t *testing.T) {
	freshRejects(t)
	buf := captureLog(t)

	for _, what := range []string{"heartbeat", "отправлено ПО", "отправлено служб"} {
		rejects.report(what, 403, "bad signature")
	}

	if n := strings.Count(buf.String(), "HTTP 403"); n != 1 {
		t.Errorf("в журнале %d сообщений об одной причине, ожидалось 1:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "heartbeat") {
		t.Error("первое сообщение должно называть, что именно отвергнуто")
	}
}

// TestRejectDifferentCausesBothLogged — выдержка не должна прятать другую беду.
func TestRejectDifferentCausesBothLogged(t *testing.T) {
	freshRejects(t)
	buf := captureLog(t)

	rejects.report("heartbeat", 403, "bad signature")
	rejects.report("heartbeat", 409, "already registered")

	out := buf.String()
	if !strings.Contains(out, "HTTP 403") || !strings.Contains(out, "HTTP 409") {
		t.Errorf("разные причины должны попасть в журнал обе:\n%s", out)
	}
}

// TestRejectClearAfterSuccess — вернувшаяся после успеха беда должна прозвучать
// сразу, а не дожидаться конца выдержки.
func TestRejectClearAfterSuccess(t *testing.T) {
	freshRejects(t)
	buf := captureLog(t)

	rejects.report("heartbeat", 403, "bad signature")
	rejects.clear() // как после удачного обмена
	rejects.report("heartbeat", 403, "bad signature")

	if n := strings.Count(buf.String(), "HTTP 403"); n != 2 {
		t.Errorf("после успешного обмена сообщение должно повториться, получено %d:\n%s",
			n, buf.String())
	}
}

// TestReportOnceThrottles — та же выдержка для сообщений без кода ответа
// (обрыв связи повторяется каждые 15 секунд).
func TestReportOnceThrottles(t *testing.T) {
	freshRejects(t)
	buf := captureLog(t)

	for i := 0; i < 4; i++ {
		rejects.reportOnce("net|dial timeout", "нет связи с сервером: dial timeout")
	}
	if n := strings.Count(buf.String(), "нет связи"); n != 1 {
		t.Errorf("получено %d сообщений, ожидалось 1:\n%s", n, buf.String())
	}
}
