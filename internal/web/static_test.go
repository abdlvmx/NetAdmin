package web

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// На каждой странице выполняются три скрипта: layout.js, search.js (для
// вошедших) и скрипт самой страницы. Это обычные скрипты, а не модули, поэтому
// область имён у них общая.
//
// Тест закрывает ошибку, которая жила незаметно: в search.js функции объявлены
// внутри блока `if (box) { … }`, а такие объявления по правилам
// веб-совместимости всплывают наружу. Функция render оттуда перекрывала
// одноимённую функцию карты сети, и карта переставала рисоваться — при том, что
// фильтры и панель проблем на той же странице работали, и заподозрить скрипт
// было не в чем.
var (
	// имя функции при любом отступе: в необёрнутом скрипте наружу всплывают
	// и объявления внутри блоков
	reFunc = regexp.MustCompile(`(?m)^\s*function\s+([A-Za-z_$][\w$]*)`)
	// скрипты, выполняющиеся на каждой странице рядом со страничным
	everyPage = []string{"layout.js", "search.js"}
)

// wrapped — скрипт целиком завёрнут в функцию, значит наружу ничего не течёт.
func wrapped(src string) bool {
	body := strings.TrimSpace(stripComments(src))
	return strings.HasPrefix(body, "(function") && strings.HasSuffix(body, "})();")
}

// stripComments убирает ведущие строки-комментарии, чтобы найти первый код.
func stripComments(src string) string {
	var out []string
	skipping := true
	for _, l := range strings.Split(src, "\n") {
		t := strings.TrimSpace(l)
		if skipping && (t == "" || strings.HasPrefix(t, "//")) {
			continue
		}
		skipping = false
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// globalFuncs — имена, которые скрипт отдаёт в общую область. У завёрнутого
// в функцию таких нет.
func globalFuncs(t *testing.T, name string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("static", name))
	if err != nil {
		t.Fatalf("чтение %s: %v", name, err)
	}
	src := string(b)
	names := map[string]bool{}
	if wrapped(src) {
		return names
	}
	for _, m := range reFunc.FindAllStringSubmatch(src, -1) {
		names[m[1]] = true
	}
	return names
}

func TestPageScriptsDoNotShareGlobalNames(t *testing.T) {
	entries, err := os.ReadDir("static")
	if err != nil {
		t.Fatalf("каталог static: %v", err)
	}

	shared := map[string]string{} // имя -> где объявлено
	for _, name := range everyPage {
		for fn := range globalFuncs(t, name) {
			shared[fn] = name
		}
	}

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".js") {
			continue
		}
		isEveryPage := false
		for _, p := range everyPage {
			isEveryPage = isEveryPage || p == name
		}
		if isEveryPage {
			continue
		}
		var clash []string
		for fn := range globalFuncs(t, name) {
			if where, ok := shared[fn]; ok {
				clash = append(clash, fn+" (уже есть в "+where+")")
			}
		}
		if len(clash) > 0 {
			sort.Strings(clash)
			t.Errorf("%s объявляет имена, занятые скриптами каждой страницы: %s\n"+
				"Оберните скрипт в (function () { … })();, иначе одна из функций молча "+
				"перекроет другую.", name, strings.Join(clash, ", "))
		}
	}
}

// TestScriptsWithBlockFunctionsAreWrapped — функции, объявленные внутри блока,
// в обычном скрипте всплывают наружу. Такой скрипт обязан быть обёрнут: иначе
// он раздаёт в общую область имена, которых сам за собой не числит.
func TestScriptsWithBlockFunctionsAreWrapped(t *testing.T) {
	entries, err := os.ReadDir("static")
	if err != nil {
		t.Fatalf("каталог static: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".js") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("static", name))
		if err != nil {
			t.Fatalf("чтение %s: %v", name, err)
		}
		src := string(b)
		if wrapped(src) {
			continue
		}
		for _, m := range reFunc.FindAllStringSubmatch(src, -1) {
			line := m[0]
			if strings.HasPrefix(line, "function") {
				continue // объявление верхнего уровня — видно и ожидаемо
			}
			t.Errorf("%s: функция %q объявлена внутри блока и всплывёт в общую "+
				"область. Оберните скрипт в (function () { … })();",
				name, m[1])
		}
	}
}

// TestSharedHelpersAreExported — скрипты страниц зовут помощников из layout.js
// (уведомление toast, модальные окна) по имени. Пока всё было глобальным, это
// работало само; после того как скрипты завернули в функции, такой вызов стал
// возможен только через window.
//
// Тест написан по следам поломки: обёртка молча оторвала уведомления у
// сканирования сети, пинга, скана портов и удалённых команд. Внешне это
// выглядело как «нажал Сканировать — Ошибка», хотя сканирование проходило.
func TestSharedHelpersAreExported(t *testing.T) {
	layout, err := os.ReadFile(filepath.Join("static", "layout.js"))
	if err != nil {
		t.Fatalf("layout.js: %v", err)
	}
	src := string(layout)

	// что layout.js объявляет у себя
	declared := map[string]bool{}
	for _, m := range reFunc.FindAllStringSubmatch(src, -1) {
		declared[m[1]] = true
	}
	// и что из этого отдал наружу
	exported := map[string]bool{}
	for _, m := range regexp.MustCompile(`window\.(\w+)\s*=`).FindAllStringSubmatch(src, -1) {
		exported[m[1]] = true
	}

	entries, err := os.ReadDir("static")
	if err != nil {
		t.Fatalf("каталог static: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".js") || name == "layout.js" {
			continue
		}
		b, err := os.ReadFile(filepath.Join("static", name))
		if err != nil {
			t.Fatalf("чтение %s: %v", name, err)
		}
		page := string(b)
		// имена, объявленные в самом страничном скрипте, не в счёт
		own := map[string]bool{}
		for _, m := range reFunc.FindAllStringSubmatch(page, -1) {
			own[m[1]] = true
		}
		for fn := range declared {
			if own[fn] || exported[fn] {
				continue
			}
			if regexp.MustCompile(`(^|[^\w.])` + fn + `\s*\(`).MatchString(page) {
				t.Errorf("%s зовёт %s() из layout.js, но layout.js его не отдаёт наружу. "+
					"Добавьте window.%s = %s; — иначе вызов упадёт с ReferenceError.",
					name, fn, fn, fn)
			}
		}
	}
}
