package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"netadmin/internal/auth"
)

// Проверка прав доступа по всей таблице маршрутов.
//
// Смысл этих тестов — не в том, что права расставлены сегодня (это видно и
// глазами), а в том, что маршрут, добавленный завтра без проверки, уронит
// сборку. Поэтому список маршрутов не переписан в тест руками, а читается из
// app.go: иначе тест защищал бы ровно от того, о чём уже известно.

type routeDecl struct {
	method  string // GET | POST
	pattern string // как записано в app.go, например "/devices/{id}/delete"
	handler string // имя метода App
}

// routesFromSource разбирает app.go и возвращает все маршруты, зарегистрированные
// вызовами mux.HandleFunc("<METHOD> <path>", a.Handler).
func routesFromSource(t *testing.T) []routeDecl {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "app.go", nil, 0)
	if err != nil {
		t.Fatalf("разбор app.go: %v", err)
	}

	var out []routeDecl
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "HandleFunc" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		method, path, found := strings.Cut(pattern, " ")
		if !found {
			return true
		}
		name := "<inline>"
		if h, ok := call.Args[1].(*ast.SelectorExpr); ok {
			name = h.Sel.Name
		}
		out = append(out, routeDecl{method: method, pattern: path, handler: name})
		return true
	})

	// Страховка от молчаливой поломки разбора: если формат регистрации
	// маршрутов изменится, тест обязан упасть, а не «пройти» на пустом списке.
	if len(out) < 80 {
		t.Fatalf("из app.go разобрано только %d маршрутов — похоже, разбор сломался", len(out))
	}
	return out
}

// requestPath подставляет значения вместо шаблонных сегментов: {id} → 1.
func requestPath(pattern string) string {
	if pattern == "/{$}" {
		return "/"
	}
	parts := strings.Split(pattern, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			parts[i] = "1"
		}
	}
	return strings.Join(parts, "/")
}

// publicPost — маршруты, которым проверка прав не нужна по устройству продукта.
// Каждый с причиной: пустых исключений тут быть не должно.
var publicPost = map[string]string{
	"/login":            "форма входа — до входа прав ещё нет",
	"/setup":            "мастер первого запуска, работает только на пустой базе",
	"/logout":           "выход доступен любому вошедшему",
	"/help/submit":      "публичный портал заявок: сотрудник без учётной записи",
	"/help/track/reply": "ответ заявителя по коду заявки, тоже без входа",
	"/settings/password": "смена собственного пароля — право любой роли, " +
		"viewer меняет только свой",
}

// publicGet — страницы, открытые без входа.
var publicGet = map[string]string{
	"/{$}":               "корень сам решает: на вход или на дашборд",
	"/login":             "страница входа",
	"/setup":             "мастер первого запуска",
	"/healthz":           "проба живости для служб и мониторинга",
	"/help":              "публичный портал заявок",
	"/help/track":        "отслеживание заявки по коду",
	"/api/agent-package": "скачивание дистрибутива агентом: подпись вместо сессии",
	// Установка агента идёт на машине, где сессии нет и быть не может.
	// Секрета маршруты не содержат: enrollment-токен администратор
	// подставляет сам, копируя команду со страницы «Настройки» за логином.
	"/enroll.ps1": "скрипт установки агента: выполняется на устанавливаемой машине",
	"/agent.exe":  "сборка агента для установки: не секрет, доступ ограничен подсетями",
}

// isAgentRoute — эндпоинты агента: они авторизуются подписью HMAC, а не сессией,
// и намеренно исключены из CSRF. Их права проверяются в agent_protocol_test.go.
func isAgentRoute(path string) bool { return strings.HasPrefix(path, "/api/agent-") }

// seedAccessUsers заводит учётные записи для проверок доступа. Без хотя бы
// одного пользователя база считается новой, и вход уводит на мастер первого
// запуска, а не на форму входа, — тогда тест проверял бы не то.
func seedAccessUsers(t *testing.T, a *App) {
	t.Helper()
	hash, _ := auth.HashPassword("Parol12345")
	for _, u := range []struct{ name, role string }{
		{"admin", "admin"},
		{"viewer", "viewer"},
	} {
		if _, err := a.DB.Exec(`INSERT INTO users (username, full_name, role, password_hash, is_active)
			VALUES (?,?,?,?,1)`, u.name, u.name, u.role, hash); err != nil {
			t.Fatalf("создание %s: %v", u.name, err)
		}
	}
}

// viewerRequest выполняет запрос от имени пользователя с ролью viewer.
func viewerRequest(t *testing.T, a *App, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	var id int64
	if err := a.DB.QueryRow("SELECT id FROM users WHERE username='viewer'").Scan(&id); err != nil {
		t.Fatalf("нет тестового viewer: %v", err)
	}
	token, err := auth.CreateSession(a.DB, id)
	if err != nil {
		t.Fatalf("сессия: %v", err)
	}

	req := httptest.NewRequest(method, path, strings.NewReader("csrf_token=t0ken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Локальный адрес: иначе запрос отобьётся фильтром подсетей — и тест
	// «прошёл» бы, ничего не проверив.
	req.RemoteAddr = "127.0.0.1:40000"
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	req.AddCookie(&http.Cookie{Name: "csrf", Value: "t0ken"})
	req.Header.Set("X-CSRF-Token", "t0ken")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Каждый изменяющий маршрут обязан отказать роли viewer.
func TestEveryWriteRouteRejectsViewer(t *testing.T) {
	a := newTestApp(t)
	seedAccessUsers(t, a)
	h := a.Routes()

	checked := 0
	for _, r := range routesFromSource(t) {
		if r.method != "POST" || isAgentRoute(r.pattern) {
			continue
		}
		if _, ok := publicPost[r.pattern]; ok {
			continue
		}
		checked++
		rec := viewerRequest(t, a, h, "POST", requestPath(r.pattern))
		body := rec.Body.String()

		// Отказ должен прийти именно от проверки прав. Фильтр подсетей и CSRF
		// отвечают тем же кодом 403 — если тест поймает их, он окажется
		// зелёным, ничего не проверив.
		switch {
		case strings.Contains(body, "CSRF"):
			t.Errorf("%s %s (%s): отклонён из-за CSRF, а не прав — проверка не состоялась",
				r.method, r.pattern, r.handler)
		case strings.Contains(body, "доступ из этой сети"):
			t.Errorf("%s %s (%s): отклонён фильтром подсетей — проверка не состоялась",
				r.method, r.pattern, r.handler)
		case rec.Code == http.StatusForbidden:
			// правильный отказ
		case rec.Code == http.StatusFound && strings.Contains(rec.Header().Get("Location"), "/login"):
			// тоже отказ: маршрут отправил на вход
		default:
			t.Errorf("%s %s (%s): viewer получил %d — маршрут не проверяет права\n"+
				"добавьте проверку роли в обработчик либо, если маршрут открыт намеренно, "+
				"внесите его в publicPost с обоснованием",
				r.method, r.pattern, r.handler, rec.Code)
		}
	}
	if checked == 0 {
		t.Fatal("не проверено ни одного маршрута — список исключений съел всё")
	}
	t.Logf("проверено изменяющих маршрутов: %d", checked)
}

// Каждая непубличная страница обязана требовать входа.
func TestEveryPageRequiresLogin(t *testing.T) {
	a := newTestApp(t)
	seedAccessUsers(t, a)
	h := a.Routes()

	checked := 0
	for _, r := range routesFromSource(t) {
		if r.method != "GET" || isAgentRoute(r.pattern) {
			continue
		}
		if _, ok := publicGet[r.pattern]; ok {
			continue
		}
		checked++
		// Часть страниц отправляет анонима не прямо на /login, а на /dashboard,
		// который уже отправляет на вход. Важно не число прыжков, а то, что
		// содержимое страницы аноним так и не увидит, — поэтому идём по цепочке.
		path, code, body := requestPath(r.pattern), 0, ""
		for hop := 0; hop < 4; hop++ {
			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = "127.0.0.1:40000" // иначе отобьёт фильтр подсетей
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			code, body = rec.Code, rec.Body.String()
			if code != http.StatusFound && code != http.StatusSeeOther {
				break
			}
			path = rec.Header().Get("Location")
		}

		if strings.Contains(body, "доступ из этой сети") {
			t.Errorf("GET %s (%s): отклонён фильтром подсетей — проверка не состоялась",
				r.pattern, r.handler)
			continue
		}
		if code != http.StatusForbidden && !strings.HasPrefix(path, "/login") {
			t.Errorf("GET %s (%s): аноним дошёл до %s с кодом %d вместо страницы входа\n"+
				"добавьте проверку сессии либо внесите путь в publicGet с обоснованием",
				r.pattern, r.handler, path, code)
		}
	}
	if checked == 0 {
		t.Fatal("не проверено ни одной страницы — список исключений съел всё")
	}
	t.Logf("проверено страниц: %d", checked)
}

// Списки исключений должны описывать существующие маршруты: путь, которого уже
// нет, — это забытая строка, из-за которой однажды пропустят настоящий маршрут
// с таким же именем.
func TestAccessExceptionsAreCurrent(t *testing.T) {
	routes := routesFromSource(t)
	has := func(method, path string) bool {
		for _, r := range routes {
			if r.method == method && r.pattern == path {
				return true
			}
		}
		return false
	}
	for path := range publicPost {
		if !has("POST", path) {
			t.Errorf("publicPost: маршрута POST %s больше нет — уберите исключение", path)
		}
	}
	for path := range publicGet {
		if !has("GET", path) {
			t.Errorf("publicGet: маршрута GET %s больше нет — уберите исключение", path)
		}
	}
}
