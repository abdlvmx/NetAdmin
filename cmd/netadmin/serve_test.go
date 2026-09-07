package main

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// Занятый адрес не должен гасить процесс.
//
// Прежде ошибка ListenAndServe уходила в log.Fatalf прямо из горутины, то есть
// в os.Exit: база не закрывалась, метрики из буфера ingest терялись, а служба
// умирала, не сообщив диспетчеру ни кода, ни причины — в журнале оставалось
// «terminated unexpectedly», и настроенные действия восстановления загоняли её
// в цикл перезапусков.
//
// Тест держится на том же: если serve снова начнёт звать os.Exit, тестовый
// процесс умрёт вместе с ним, и пакет упадёт целиком.
func TestServeReportsBusyAddressInsteadOfExiting(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("занять адрес для проверки: %v", err)
	}
	defer busy.Close()

	// Каталог данных убирается вручную: t.TempDir() на Windows падает с
	// «directory is not empty», когда рядом с базой ещё лежат файлы WAL, и
	// прошедший тест помечается как FAIL.
	dir, err := os.MkdirTemp("", "netadmin-serve-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	t.Setenv("NETADMIN_DATA_DIR", dir)
	t.Setenv("NETADMIN_ADDR", busy.Addr().String())
	t.Setenv("NETADMIN_NO_BROWSER", "1")

	done := make(chan error, 1)
	go func() { done <- serve(false, make(chan struct{})) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("сервер занял недоступный адрес и не пожаловался")
		}
		// Отказ обязан называть адрес: иначе непонятно, что именно занято.
		if !strings.Contains(err.Error(), busy.Addr().String()) {
			t.Errorf("в отказе нет адреса %s: %v", busy.Addr(), err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve не вернулся: ошибка прослушивания до него не дошла")
	}
}
