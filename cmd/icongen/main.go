// Команда icongen рисует значок продукта и раскладывает его по местам, где он
// нужен: в сам .exe, во вкладку браузера и в ярлык на рабочем столе.
//
// Инструмент разработчика, как и cmd/seed: в готовый сервер не входит и при
// обычной сборке не запускается. Всё, что он рисует, лежит в репозитории
// готовым — `go build` не требует ни его, ни внешних программ.
//
// Значок собран из тех же двух фигур, что и плашка в боковом меню: скруглённый
// квадрат и щит внутри. Разница одна, и она вынужденная. В интерфейсе плашка
// серая, потому что рядом с ней стоит подпись «NetAdmin» и кричать незачем;
// в панели задач и в «Проводнике» рядом не стоит ничего, и серый щит на сером
// фоне не виден вовсе. Поэтому здесь квадрат акцентного цвета, а щит белый —
// композиция та же, контраст другой.
//
// Перерисовать всё после правки геометрии:
//
//	go run ./cmd/icongen
//	go run github.com/akavel/rsrc@v0.10.2 -ico cmd/netadmin/netadmin.ico -arch amd64 -o cmd/netadmin/rsrc_windows_amd64.syso
//	go run github.com/akavel/rsrc@v0.10.2 -ico cmd/netadmin/netadmin.ico -arch amd64 -o cmd/agent/rsrc_windows_amd64.syso
//
// Второй и третий шаги — единственное место, где нужна сеть, и нужны они
// только при перерисовке: .syso лежат в репозитории собранными.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ===== Геометрия =====
//
// Считаем в тех же 24 единицах, в которых нарисован спрайт интерфейса, — тогда
// щит здесь и щит в меню задаются одними и теми же числами.

const (
	unit = 24.0

	// Скругление плашки — 22% стороны, та же доля, что у .sidebar-logo .mark
	// в layout.html (радиус 6px при стороне 30px).
	plaqueRadius = 0.22 * unit

	// Высота щита — 55% стороны. Больше — щит подходит к углам плашки и на
	// мелких гранях сливается с ней в белое пятно; меньше — теряется в поле.
	shieldHeight = 0.55 * unit

	// Щит сужается книзу, поэтому его видимая масса собрана вверху: по
	// геометрическому центру он кажется задранным. Полпроцента стороны вниз
	// хватает, чтобы это ушло.
	shieldNudgeY = 0.005 * unit
)

// shieldPathD — контур щита ровно в том виде, в каком он лежит в спрайте
// (символ i-shield в layout.html). Строка обязана совпадать посимвольно:
// на неё смотрит тест, иначе значок и меню однажды разъедутся, и заметить это
// будет негде.
const shieldPathD = "M12 3l8 3v6c0 5-3.5 8.5-8 9.5-4.5-1-8-4.5-8-9.5V6z"

var (
	// --accent из layout.html: единственный акцентный цвет продукта.
	plaqueColor = color.NRGBA{R: 0x2f, G: 0x4a, B: 0x7a, A: 0xff}
	shieldColor = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
)

type pt struct{ x, y float64 }

// shieldOutline разбирает shieldPathD в ломаную.
//
// Разбор ручной, а не парсером SVG: путь один, он короткий и меняться не
// должен, а зависимость ради него тянуть некуда — их в проекте нет.
//
//	M12 3                    → (12,3)
//	l8 3                     → (20,6)
//	v6                       → (20,12)
//	c0 5 -3.5 8.5 -8 9.5     → кривая до (12,21.5)
//	c-4.5 -1 -8 -4.5 -8 -9.5 → кривая до (4,12)
//	V6                       → (4,6)
//	z                        → замыкание на (12,3)
func shieldOutline() []pt {
	p := []pt{{12, 3}, {20, 6}, {20, 12}}
	p = appendCubic(p, pt{20, 12}, pt{20, 17}, pt{16.5, 20.5}, pt{12, 21.5})
	p = appendCubic(p, pt{12, 21.5}, pt{7.5, 20.5}, pt{4, 17}, pt{4, 12})
	return append(p, pt{4, 6})
}

// appendCubic превращает кубическую кривую в отрезки. Шагов заведомо больше,
// чем нужно: рисуем один раз, и лишняя сотня точек не стоит ничего.
func appendCubic(dst []pt, p0, c1, c2, p3 pt) []pt {
	const steps = 48
	for i := 1; i <= steps; i++ {
		t := float64(i) / steps
		u := 1 - t
		a, b, c, d := u*u*u, 3*u*u*t, 3*u*t*t, t*t*t
		dst = append(dst, pt{
			x: a*p0.x + b*c1.x + c*c2.x + d*p3.x,
			y: a*p0.y + b*c1.y + c*c2.y + d*p3.y,
		})
	}
	return dst
}

// shieldTransform — сдвиг и масштаб, вписывающие контур в плашку. Возвращает
// ровно то, что уходит в SVG атрибутом transform: растр и вектор считаются
// отсюда оба и разойтись не могут.
func shieldTransform() (tx, ty, scale float64) {
	minX, minY, maxX, maxY := bbox(shieldOutline())
	scale = shieldHeight / (maxY - minY)
	// центрируем габарит контура в плашке
	tx = (unit-(maxX-minX)*scale)/2 - minX*scale
	ty = (unit-(maxY-minY)*scale)/2 - minY*scale + shieldNudgeY
	return tx, ty, scale
}

// shieldPlaced — контур, уже поставленный на плашку.
func shieldPlaced() []pt {
	tx, ty, k := shieldTransform()
	p := shieldOutline()
	out := make([]pt, len(p))
	for i, q := range p {
		out[i] = pt{x: q.x*k + tx, y: q.y*k + ty}
	}
	return out
}

func bbox(p []pt) (minX, minY, maxX, maxY float64) {
	minX, minY, maxX, maxY = p[0].x, p[0].y, p[0].x, p[0].y
	for _, q := range p {
		minX, maxX = min(minX, q.x), max(maxX, q.x)
		minY, maxY = min(minY, q.y), max(maxY, q.y)
	}
	return minX, minY, maxX, maxY
}

// ===== Растеризация =====

// render рисует значок стороной size пикселей.
//
// Сглаживания в стандартной библиотеке нет, поэтому считаем в лоб: каждый
// пиксель разбиваем на ss×ss проб и усредняем. Каждая проба либо целиком
// закрашена, либо целиком пуста, так что цвет — обычное среднее по закрашенным,
// а прозрачность — их доля.
func render(size int) *image.NRGBA {
	const ss = 4 // проб на сторону пикселя
	poly := shieldPlaced()
	minX, minY, maxX, maxY := bbox(poly)

	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	n := float64(size * ss)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var covered, r, g, b float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					u := (float64(px*ss+sx) + 0.5) / n * unit
					v := (float64(py*ss+sy) + 0.5) / n * unit
					if !inRoundRect(u, v) {
						continue
					}
					c := plaqueColor
					if u >= minX && u <= maxX && v >= minY && v <= maxY && inPolygon(poly, u, v) {
						c = shieldColor
					}
					covered++
					r, g, b = r+float64(c.R), g+float64(c.G), b+float64(c.B)
				}
			}
			if covered == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{
				R: uint8(r/covered + 0.5),
				G: uint8(g/covered + 0.5),
				B: uint8(b/covered + 0.5),
				A: uint8(covered/(ss*ss)*255 + 0.5),
			})
		}
	}
	return img
}

// inRoundRect — точка внутри скруглённого квадрата плашки.
func inRoundRect(x, y float64) bool {
	if x < 0 || y < 0 || x > unit || y > unit {
		return false
	}
	// Ближайшая точка квадрата, сжатого на радиус: в прямых частях она лежит
	// на одной прямой с пробой и расстояние выходит нулевым, в углах — даёт
	// нужную окружность.
	cx := min(max(x, plaqueRadius), unit-plaqueRadius)
	cy := min(max(y, plaqueRadius), unit-plaqueRadius)
	dx, dy := x-cx, y-cy
	return dx*dx+dy*dy <= plaqueRadius*plaqueRadius
}

// inPolygon — проба внутри ломаной (число пересечений луча вправо).
func inPolygon(p []pt, x, y float64) bool {
	in := false
	for i, j := 0, len(p)-1; i < len(p); j, i = i, i+1 {
		if (p[i].y > y) == (p[j].y > y) {
			continue
		}
		xi := p[i].x + (y-p[i].y)*(p[j].x-p[i].x)/(p[j].y-p[i].y)
		if x < xi {
			in = !in
		}
	}
	return in
}

// ===== Формат .ico =====

type icoEntry struct {
	size int
	data []byte
}

// encodePNG — грань в PNG. Крупные грани значка .exe и все грани значка
// вкладки хранятся так: заливка ровная, и PNG ужимает её до сотен байт вместо
// десятков килобайт несжатого DIB.
func encodePNG(img *image.NRGBA) []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err) // кодирование картинки в память отказать не может
	}
	return buf.Bytes()
}

// encodeDIB — грань в том виде, в каком значки хранились всегда:
// BITMAPINFOHEADER, строки снизу вверх, BGRA.
//
// Мелкие грани значка .exe идут именно так. PNG внутри .ico понимает Windows
// Vista и новее, но отдельные пути «Проводника» и старые диалоги до сих пор
// разбирают только этот формат, а значок в них — первое, что видит человек.
func encodeDIB(img *image.NRGBA) []byte {
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	var buf bytes.Buffer
	put := func(v any) { _ = binary.Write(&buf, binary.LittleEndian, v) }

	put(uint32(40))   // biSize
	put(int32(w))     // biWidth
	put(int32(2 * h)) // biHeight — цвет и маска прозрачности подряд
	put(uint16(1))    // biPlanes
	put(uint16(32))   // biBitCount
	put(uint32(0))    // biCompression = BI_RGB
	put(uint32(0))    // biSizeImage
	put(int32(0))     // biXPelsPerMeter
	put(int32(0))     // biYPelsPerMeter
	put(uint32(0))    // biClrUsed
	put(uint32(0))    // biClrImportant

	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.NRGBAAt(x, y)
			buf.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	// Маска прозрачности. У 32-битной грани её роль исполняет альфа-канал, но
	// по формату маска обязана присутствовать: нули — «показывать всё».
	rowBytes := ((w + 31) / 32) * 4
	buf.Write(make([]byte, rowBytes*h))
	return buf.Bytes()
}

// writeICO собирает файл значка из готовых граней.
func writeICO(entries []icoEntry) []byte {
	var head, body bytes.Buffer
	offset := 6 + 16*len(entries)
	_ = binary.Write(&head, binary.LittleEndian, [3]uint16{0, 1, uint16(len(entries))})
	for _, e := range entries {
		// 256 в байт не помещается и записывается нулём — так задумано форматом
		dim := byte(e.size)
		_ = binary.Write(&head, binary.LittleEndian, struct {
			W, H, Colors, Reserved uint8
			Planes, Bits           uint16
			Size, Offset           uint32
		}{dim, dim, 0, 0, 1, 32, uint32(len(e.data)), uint32(offset)})
		body.Write(e.data)
		offset += len(e.data)
	}
	return append(head.Bytes(), body.Bytes()...)
}

// ===== Вывод =====

// appIcon — значок для .exe и ярлыка.
//
// Граней много, потому что Windows берёт ближайшую, а не масштабирует красиво:
// 16 в панели задач, 32 в списке «Проводника», 48 на рабочем столе, 256 в
// режиме крупных значков, остальные — под масштабирование экрана (125%, 150%,
// 200%).
func appIcon() []byte {
	var out []icoEntry
	for _, s := range []int{16, 20, 24, 32, 40, 48} {
		out = append(out, icoEntry{size: s, data: encodeDIB(render(s))})
	}
	for _, s := range []int{64, 96, 128, 256} {
		out = append(out, icoEntry{size: s, data: encodePNG(render(s))})
	}
	return writeICO(out)
}

// webIcon — запасной значок вкладки для браузеров, которые не берут SVG.
// Три грани и все в PNG: файл уходит по сети, и весить он должен килобайт,
// а не тридцать.
func webIcon() []byte {
	var out []icoEntry
	for _, s := range []int{16, 32, 48} {
		out = append(out, icoEntry{size: s, data: encodePNG(render(s))})
	}
	return writeICO(out)
}

// webSVG — основной значок вкладки: он один остаётся резким на любом масштабе
// и весит меньше самой мелкой грани растра.
//
// Путь щита вписан той же строкой, что лежит в спрайте, а вся подгонка вынесена
// в transform — тогда файл можно сверить с layout.html глазами, а тест сверяет
// его сам.
func webSVG() []byte {
	tx, ty, k := shieldTransform()
	return []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <rect width="24" height="24" rx="` + num(plaqueRadius) + `" fill="#2f4a7a"/>
  <path transform="translate(` + num(tx) + ` ` + num(ty) + `) scale(` + num(k) + `)"
        d="` + shieldPathD + `" fill="#ffffff"/>
</svg>
`)
}

// num — короткая запись числа для SVG: без хвостовых нулей.
func num(v float64) string {
	s := strconv.FormatFloat(v, 'f', 4, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(s, "0")
		s = strings.TrimSuffix(s, ".")
	}
	return s
}

func main() {
	// Запуск только из корня репозитория: иначе файлы разъедутся по случайным
	// каталогам, и найти их будет труднее, чем перерисовать заново.
	if _, err := os.Stat("go.mod"); err != nil {
		fmt.Println("ОШИБКА: запускать из корня репозитория (рядом с go.mod)")
		os.Exit(1)
	}

	files := []struct {
		path string
		data []byte
	}{
		{filepath.Join("cmd", "netadmin", "netadmin.ico"), appIcon()},
		{filepath.Join("internal", "web", "static", "favicon.ico"), webIcon()},
		{filepath.Join("internal", "web", "static", "favicon.svg"), webSVG()},
	}
	for _, f := range files {
		if err := os.WriteFile(f.path, f.data, 0o644); err != nil {
			fmt.Println("ОШИБКА:", err)
			os.Exit(1)
		}
		fmt.Printf("  %-40s %7d Б\n", f.path, len(f.data))
	}
	fmt.Println()
	fmt.Println("Значок внутри .exe пересобирается отдельно — см. комментарий в cmd/icongen/main.go.")
}
