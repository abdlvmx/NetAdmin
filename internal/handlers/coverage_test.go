package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

// Покрытие агентами считается по устройствам с персональным токеном.
//
// Отфильтровать машины без агента страница устройств умела и раньше, а вот
// ответить «сколько их всего и сколько осталось» можно было только счётом строк
// глазами — то есть на вопрос «всё ли я раскатал» продукт не отвечал.
func TestAgentCoverageCounted(t *testing.T) {
	app := newTestApp(t)
	deviceWithAgent(t, app, "PC-1", "токен-1")
	deviceWithAgent(t, app, "PC-2", "токен-2")
	if _, err := app.DB.Exec("INSERT INTO devices (hostname, status) VALUES ('PC-3','online')"); err != nil {
		t.Fatal(err)
	}
	// Хост, найденный в сети и ещё не заведённый устройством: для раскатки
	// это такая же цель, но живёт он в другой таблице.
	if _, err := app.DB.Exec(`INSERT INTO discovery_queue (ip, mac, status)
		VALUES ('192.168.1.9','aa:bb:cc:dd:ee:ff','new')`); err != nil {
		t.Fatal(err)
	}

	s := app.dashboardStats()
	if s.DevicesWithAgent != 2 || s.DevicesNoAgent != 1 || s.DevicesTotal != 3 {
		t.Errorf("получено с агентом=%d без агента=%d всего=%d, ожидалось 2/1/3",
			s.DevicesWithAgent, s.DevicesNoAgent, s.DevicesTotal)
	}
	if s.AgentCoveragePct != 67 {
		t.Errorf("покрытие %d%%, ожидалось 67%%", s.AgentCoveragePct)
	}
	if s.DiscoveredNew != 1 {
		t.Errorf("найденных в сети %d, ожидался 1", s.DiscoveredNew)
	}
}

// Пустая база не должна давать ни деления на ноль, ни ложной тревоги.
func TestAgentCoverageOnEmptyBase(t *testing.T) {
	app := newTestApp(t)
	s := app.dashboardStats()
	if s.AgentCoveragePct != 0 || s.DevicesNoAgent != 0 {
		t.Errorf("на пустой базе получено %d%% и %d без агента", s.AgentCoveragePct, s.DevicesNoAgent)
	}
}

// Плитка ведёт на список устройств с уже выставленным фильтром: иначе от неё
// пришлось бы идти к фильтру руками, а это ровно то, что она и экономит.
func TestCoverageTileLinksToFilteredList(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "dashboard", dashData{
		User:   &auth.User{ID: 1, Username: "admin", Role: "admin"},
		Active: "dashboard",
		Stats:  dashStats{DevicesTotal: 3, DevicesWithAgent: 2, DevicesNoAgent: 1, AgentCoveragePct: 67},
	})

	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка выполнения шаблона: %s", body)
	}
	if !strings.Contains(body, `href="/devices?agent=no"`) {
		t.Error("плитка не ведёт на список устройств без агента")
	}
	if !strings.Contains(body, "Покрытие агентами") || !strings.Contains(body, "1 без агента") {
		t.Errorf("плитка показана не полностью:\n%s", body)
	}
}
