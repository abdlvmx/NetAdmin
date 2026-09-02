package handlers

import (
	"strings"
	"testing"
)

// Значение для .rdp не должно содержать переводов строк: иначе имя устройства
// дописывает в файл собственные настройки RDP.
func TestRDPValueStripsControlChars(t *testing.T) {
	evil := "192.168.1.5\r\nalternate shell:s:cmd.exe"
	got := rdpValue(evil)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("перевод строки остался в значении: %q", got)
	}
	if strings.Contains(got, "\nalternate shell") {
		t.Fatalf("удалось дописать строку настройки: %q", got)
	}
	if rdpValue("192.168.1.5") != "192.168.1.5" {
		t.Error("обычный адрес не должен меняться")
	}
}

func TestSanitizeFilenameStripsControlChars(t *testing.T) {
	got := sanitizeFilename("отчёт\r\nX-Injected: 1")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("перевод строки остался в имени файла: %q", got)
	}
	if sanitizeFilename("") != "device" {
		t.Error("пустое имя должно заменяться запасным")
	}
	if strings.ContainsAny(sanitizeFilename(`a/b\c:d`), `/\:`) {
		t.Error("разделители пути должны заменяться")
	}
}
