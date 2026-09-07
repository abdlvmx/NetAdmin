package main

import (
	"testing"
	"time"
)

// Адрес сервера вписывают руками в install_agent.bat на каждой машине, поэтому
// агент достраивает его до пригодного вида, а не падает на каждом запросе.
func TestNormalizeServerURL(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		// самая частая опечатка: ни схемы, ни порта
		{"192.168.1.64", "http://192.168.1.64:8765"},
		{"192.168.1.64:8765", "http://192.168.1.64:8765"},
		{"srv-1c", "http://srv-1c:8765"},
		// схема есть, порт забыли
		{"http://192.168.1.64", "http://192.168.1.64:8765"},
		// уже правильный адрес не трогаем
		{"http://192.168.1.64:8765", "http://192.168.1.64:8765"},
		// нестандартный порт сохраняем
		{"http://192.168.1.64:9000", "http://192.168.1.64:9000"},
		// хвостовой слеш дал бы двойной слеш в пути запроса
		{"http://192.168.1.64:8765/", "http://192.168.1.64:8765"},
		{"192.168.1.64/", "http://192.168.1.64:8765"},
		// лишние пробелы при копировании из документа
		{"  192.168.1.64  ", "http://192.168.1.64:8765"},
		// пустое значение — возвращаемся к локальному адресу по умолчанию
		{"", "http://127.0.0.1:8765"},
		{"   ", "http://127.0.0.1:8765"},
	} {
		if got := normalizeServerURL(c.in); got != c.want {
			t.Errorf("normalizeServerURL(%q) = %q, ожидалось %q", c.in, got, c.want)
		}
	}
}

// Если адрес указан с https, схему не подменяем: пользователь мог поставить
// обратный прокси перед сервером.
func TestNormalizeServerURLKeepsHTTPS(t *testing.T) {
	if got := normalizeServerURL("https://netadmin.local"); got != "https://netadmin.local:8765" {
		t.Errorf("получено %q", got)
	}
	if got := normalizeServerURL("https://netadmin.local:443"); got != "https://netadmin.local:443" {
		t.Errorf("получено %q", got)
	}
}

// Отметка «отправлено» ставится только при успехе. При отказе сервера следующая
// попытка должна прийтись через inventoryRetry, а не через полный интервал:
// иначе отвергнутый инвентарь пропадал бы на сутки.
func TestAttemptStamp(t *testing.T) {
	const day = 24 * time.Hour

	okStamp := attemptStamp(true, day)
	tOK, err := time.Parse("2006-01-02 15:04:05", okStamp)
	if err != nil {
		t.Fatalf("не разобрано %q: %v", okStamp, err)
	}
	if d := time.Since(tOK); d > time.Minute {
		t.Errorf("при успехе ожидалось текущее время, отклонение %s", d)
	}
	if dueSoftware(okStamp) {
		t.Error("сразу после успешной отправки инвентарь слать не нужно")
	}

	failStamp := attemptStamp(false, day)
	if dueSoftware(failStamp) {
		t.Error("сразу после отказа повторять нельзя — сбор дорогой")
	}
	tFail, err := time.Parse("2006-01-02 15:04:05", failStamp)
	if err != nil {
		t.Fatalf("не разобрано %q: %v", failStamp, err)
	}
	// следующая попытка примерно через inventoryRetry
	wait := day - time.Since(tFail)
	if wait < inventoryRetry-time.Minute || wait > inventoryRetry+time.Minute {
		t.Errorf("повтор ожидался через ~%s, получилось через %s", inventoryRetry, wait)
	}
}
