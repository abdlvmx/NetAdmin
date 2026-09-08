package web

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Значок вкладки рисуется отдельной командой (cmd/icongen) и при обычной сборке
// не перерисовывается: он лежит в репозитории готовым. Значит, разойтись с
// интерфейсом или пропасть он может молча — эти проверки за тем и стоят.

var (
	// щит в спрайте интерфейса
	reSpriteShield = regexp.MustCompile(`<symbol id="i-shield"[^>]*><path d="([^"]+)"`)
	// щит в значке вкладки: атрибут d может стоять и на второй строке тега
	reFaviconShield = regexp.MustCompile(`<path[^>]*\sd="([^"]+)"`)
)

// Щит на значке и щит в боковом меню — одна фигура, заданная одной строкой.
// Правка одного из двух мест без второго даёт продукт с двумя разными гербами,
// и заметить это можно только случайно.
func TestFaviconRepeatsSpriteShield(t *testing.T) {
	layout, err := os.ReadFile(filepath.Join("templates", "layout.html"))
	if err != nil {
		t.Fatalf("чтение layout.html: %v", err)
	}
	sprite := reSpriteShield.FindSubmatch(layout)
	if sprite == nil {
		t.Fatal("в layout.html не найден символ i-shield — изменилась разметка спрайта")
	}

	icon, err := StaticFile("favicon.svg")
	if err != nil {
		t.Fatalf("чтение favicon.svg: %v", err)
	}
	shield := reFaviconShield.FindSubmatch(icon)
	if shield == nil {
		t.Fatal("в favicon.svg не найден контур щита")
	}

	if !bytes.Equal(sprite[1], shield[1]) {
		t.Errorf("щит значка разошёлся со щитом интерфейса:\n"+
			"  layout.html:  %s\n  favicon.svg:  %s\n"+
			"Перерисуйте значок: см. комментарий в cmd/icongen/main.go.",
			sprite[1], shield[1])
	}
}

// Страниц с собственным <head> пять: общий layout и четыре цельных (вход,
// первый запуск, портал заявок и отслеживание). Появление шестой — обычное
// дело, и она не должна выйти с пустой вкладкой.
func TestEveryHeadAsksForFavicon(t *testing.T) {
	entries, err := os.ReadDir("templates")
	if err != nil {
		t.Fatalf("каталог templates: %v", err)
	}
	heads := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("templates", e.Name()))
		if err != nil {
			t.Fatalf("чтение %s: %v", e.Name(), err)
		}
		src := string(b)
		if !strings.Contains(src, "<head>") {
			continue // страница внутри layout, свой <head> ей не нужен
		}
		heads++
		if !strings.Contains(src, `rel="icon"`) {
			t.Errorf("%s: своя <head>, но значок вкладки не запрошен — "+
				`добавьте <link rel="icon" href="/static/favicon.svg" type="image/svg+xml">`,
				e.Name())
		}
	}
	if heads == 0 {
		t.Fatal("ни одной страницы с собственной <head> — проверка ничего не проверила")
	}
}

// Запасной растровый значок для браузеров, которые не берут SVG. Проверяем, что
// файл вообще разбирается и в нём те грани, которых от него ждут: испорченный
// или обрезанный .ico внешне неотличим от целого.
func TestFaviconICOHasExpectedSizes(t *testing.T) {
	raw, err := StaticFile("favicon.ico")
	if err != nil {
		t.Fatalf("чтение favicon.ico: %v", err)
	}
	sizes := icoSizes(t, raw)
	want := []int{16, 32, 48}
	if len(sizes) != len(want) {
		t.Fatalf("граней %d, ожидалось %d: %v", len(sizes), len(want), sizes)
	}
	for i, s := range want {
		if sizes[i] != s {
			t.Errorf("грань %d: %d вместо %d", i, sizes[i], s)
		}
	}
}

// icoSizes разбирает заголовок .ico и заодно убеждается, что данные каждой
// грани целиком лежат в файле.
func icoSizes(t *testing.T, raw []byte) []int {
	t.Helper()
	if len(raw) < 6 || binary.LittleEndian.Uint16(raw[0:2]) != 0 ||
		binary.LittleEndian.Uint16(raw[2:4]) != 1 {
		t.Fatal("это не .ico: не совпала сигнатура")
	}
	n := int(binary.LittleEndian.Uint16(raw[4:6]))
	if len(raw) < 6+16*n {
		t.Fatal(".ico обрезан: не хватает таблицы граней")
	}
	var out []int
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
		out = append(out, side)
	}
	return out
}
