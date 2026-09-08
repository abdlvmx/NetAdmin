package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Ярлык на рабочем столе — то, чем человек открывает панель каждый день. Без
// строки IconFile Windows рисует .url значком браузера по умолчанию, и NetAdmin
// лежит среди случайных закладок неотличимо от них.
func TestShortcutCarriesIcon(t *testing.T) {
	const exe = `C:\ProgramData\NetAdmin\netadmin.exe`
	body := shortcutBody(exe)

	for _, want := range []string{
		"[InternetShortcut]",
		"URL=http://127.0.0.1:8765/",
		"IconFile=" + exe,
		"IconIndex=0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("в ярлыке нет строки %q:\n%s", want, body)
		}
	}
	// .url разбирает и оболочка, и старые диалоги, а они ждут именно CRLF
	if strings.Contains(strings.ReplaceAll(body, "\r\n", ""), "\n") {
		t.Errorf("в ярлыке есть перевод строки без возврата каретки:\n%q", body)
	}
}

// Значок .exe лежит в репозитории собранным: .syso делается отдельной командой
// (см. комментарий в cmd/icongen/main.go) и при обычной сборке не
// пересоздаётся. Пропасть он поэтому может незаметно — сборка пройдёт, тесты
// пройдут, и только скачанный файл окажется у человека безымянным
// прямоугольником.
func TestAppIconIsBuiltIn(t *testing.T) {
	for _, p := range []string{
		"rsrc_windows_amd64.syso",
		filepath.Join("..", "agent", "rsrc_windows_amd64.syso"),
	} {
		st, err := os.Stat(p)
		if err != nil {
			t.Errorf("%s: %v\nПересоберите значок: см. комментарий в cmd/icongen/main.go", p, err)
			continue
		}
		// В ресурсе лежат все грани значка; десяток килобайт — заведомо ниже
		// правды, но отличает целый файл от пустого или обрезанного.
		if st.Size() < 10<<10 {
			t.Errorf("%s: всего %d Б — похоже, значок в ресурс не попал", p, st.Size())
		}
	}
}

// Грани значка перечислены явно: Windows не масштабирует значки красиво, она
// берёт ближайшую готовую. Пропажа мелких граней видна только на глаз и только
// в «Проводнике», поэтому список закреплён здесь.
func TestAppIconHasAllSizes(t *testing.T) {
	raw, err := os.ReadFile("netadmin.ico")
	if err != nil {
		t.Fatalf("чтение netadmin.ico: %v", err)
	}
	if len(raw) < 6 || binary.LittleEndian.Uint16(raw[2:4]) != 1 {
		t.Fatal("это не .ico: не совпала сигнатура")
	}
	n := int(binary.LittleEndian.Uint16(raw[4:6]))
	if len(raw) < 6+16*n {
		t.Fatal(".ico обрезан: не хватает таблицы граней")
	}

	got := map[int]bool{}
	for i := 0; i < n; i++ {
		e := raw[6+16*i : 6+16*(i+1)]
		side := int(e[0])
		if side == 0 {
			side = 256 // 256 в байт не помещается и пишется нулём
		}
		size := binary.LittleEndian.Uint32(e[8:12])
		off := binary.LittleEndian.Uint32(e[12:16])
		if int(off)+int(size) > len(raw) {
			t.Fatalf(".ico обрезан: грань %dx%d выходит за конец файла", side, side)
		}
		got[side] = true
	}

	// 16 — панель задач и списки, 32 — «Проводник», 48 — рабочий стол,
	// 256 — режим крупных значков, остальные — масштаб экрана 125/150/200%.
	for _, side := range []int{16, 20, 24, 32, 40, 48, 64, 96, 128, 256} {
		if !got[side] {
			t.Errorf("в значке нет грани %dx%d", side, side)
		}
	}
}
