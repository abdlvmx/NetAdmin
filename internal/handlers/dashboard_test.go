package handlers

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

// Смоук-тест: дашборд рендерится без ошибок шаблона.
func TestDashboardRenders(t *testing.T) {
	rec := httptest.NewRecorder()
	data := dashData{
		User:          &auth.User{ID: 1, Username: "admin", Role: "admin"},
		Active:        "dashboard",
		LastHeartbeat: "только что",
	}
	web.RenderPage(rec, "dashboard", data)

	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка выполнения шаблона: %s", body)
	}
	for _, want := range []string{"Дашборд", "Статус устройств"} {
		if !strings.Contains(body, want) {
			t.Fatalf("в выводе нет %q", want)
		}
	}
}

// Сводка «Требует внимания» показывает строки со ссылками в нужные разделы.
func TestDashboardIssuesRender(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "dashboard", dashData{
		User:   &auth.User{ID: 1, Username: "admin", Role: "admin"},
		Active: "dashboard",
		Issues: []issueGroup{
			{Cause: "Сервисы не отвечают", Crit: true, Total: 2, Href: "/monitoring", Items: []issueItem{
				{Title: "1С", Detail: "tcp 192.168.1.5:1541", Age: "12 мин", Href: "/monitoring"},
			}},
			{Cause: "Расходники и батареи на исходе", Total: 1, Href: "/snmp", Items: []issueItem{
				{Title: "Принтер", Detail: "тонер 8%", Age: "2 мин", Href: "/snmp/3/ports"},
			}},
		},
		IssuesTotal: 3,
	})
	body := rec.Body.String()
	for _, want := range []string{"Требует внимания", "Сервисы не отвечают", `href="/monitoring"`,
		"Расходники и батареи на исходе", `href="/snmp/3/ports"`,
		"1С", "tcp 192.168.1.5:1541", "12 мин", "Критично", "Внимание"} {
		if !strings.Contains(body, want) {
			t.Fatalf("в выводе нет %q", want)
		}
	}
	// Критичное отличается от того, что просто требует внимания.
	if !strings.Contains(body, "issue-dot crit") {
		t.Fatal("критичная строка должна помечаться отдельно")
	}
}

func TestDashboardIssuesEmpty(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "dashboard", dashData{
		User: &auth.User{ID: 1, Username: "admin", Role: "admin"}, Active: "dashboard",
	})
	if !strings.Contains(rec.Body.String(), "Открытых проблем нет") {
		t.Fatal("при отсутствии проблем нужна явная строка, а не пустой блок")
	}
}

// Сводка собирает проблемы из всех разделов, а не только из устройств.
func TestIssuesCollectsAllSources(t *testing.T) {
	a := newTestApp(t)
	a.DB.Exec(`INSERT INTO devices (id, hostname, status) VALUES (1,'WS-1','offline')`)
	a.DB.Exec(`INSERT INTO service_checks (name, type, target, enabled, last_status)
		VALUES ('1С','tcp','192.168.1.5:1541',1,'down')`)
	a.DB.Exec(`INSERT INTO snmp_devices (name, ip, kind, enabled, last_status, supply_alert)
		VALUES ('Принтер','192.168.1.50','printer',1,'up',1)`)
	a.DB.Exec(`INSERT INTO snmp_devices (name, ip, kind, enabled, last_status)
		VALUES ('ИБП','192.168.1.7','ups',1,'down')`)
	a.DB.Exec(`INSERT INTO disks (device_id, model, serial, health, predict_fail)
		VALUES (1,'ST1000','X1','ok',1)`)

	got := map[string]int{}
	for _, g := range a.issueGroups() {
		got[g.Cause] = g.Total
	}
	for cause, want := range map[string]int{
		"Нет связи":                      1,
		"Сервисы не отвечают":            1,
		"SNMP-устройства недоступны":     1,
		"Расходники и батареи на исходе": 1,
		"Диски: ожидается отказ":         1,
	} {
		if got[cause] != want {
			t.Errorf("%q: получено %d, ожидалось %d", cause, got[cause], want)
		}
	}
}

// Сводка называет объекты по именам и ведёт на них: ради этого она и
// переставала быть набором счётчиков.
func TestIssuesNameObjectsAndLinkToThem(t *testing.T) {
	a := newTestApp(t)
	a.DB.Exec(`INSERT INTO devices (id, hostname, status, last_seen)
		VALUES (1,'BUH-01','offline', datetime('now','-3 hours'))`)

	groups := a.issueGroups()
	if len(groups) != 1 || len(groups[0].Items) != 1 {
		t.Fatalf("ожидалась одна проблема, получено %+v", groups)
	}
	it := groups[0].Items[0]
	if it.Title != "BUH-01" {
		t.Errorf("в строке %q вместо имени машины", it.Title)
	}
	if it.Href != "/devices/1" {
		t.Errorf("строка ведёт в %q, а не на саму машину", it.Href)
	}
	if it.Age != "3 ч" {
		t.Errorf("давность %q, ожидалось «3 ч»", it.Age)
	}
}

// Сломанное показывается выше того, что только сломается: сводка отвечает на
// вопрос «с чего начать», и порядок в ней — часть ответа.
func TestIssuesPutCriticalFirst(t *testing.T) {
	a := newTestApp(t)
	a.DB.Exec(`INSERT INTO devices (id, hostname, status, cpu_usage)
		VALUES (1,'WS-1','online',95), (2,'WS-2','online',97), (3,'WS-3','offline',0)`)

	groups := a.issueGroups()
	if len(groups) < 2 {
		t.Fatalf("ожидались обе группы, получено %+v", groups)
	}
	if !groups[0].Crit {
		t.Errorf("первой идёт группа %q, а она не критическая", groups[0].Cause)
	}
	if groups[0].Total != 1 || groups[1].Total != 2 {
		t.Errorf("порядок или счёт неверны: %q=%d, %q=%d",
			groups[0].Cause, groups[0].Total, groups[1].Cause, groups[1].Total)
	}
}

// Длинный список — уже не сводка: показываем несколько строк и говорим,
// сколько осталось.
func TestIssuesTrimsLongList(t *testing.T) {
	a := newTestApp(t)
	for i := 1; i <= 7; i++ {
		a.DB.Exec(`INSERT INTO devices (hostname, status) VALUES (?, 'offline')`,
			fmt.Sprintf("WS-%d", i))
	}
	groups := a.issueGroups()
	if len(groups) != 1 {
		t.Fatalf("ожидалась одна группа: %+v", groups)
	}
	g := groups[0]
	if len(g.Items) != maxIssueItems {
		t.Errorf("показано %d строк, ожидалось %d", len(g.Items), maxIssueItems)
	}
	if g.Total != 7 || g.More != 7-maxIssueItems {
		t.Errorf("всего %d, скрыто %d — счёт не сходится", g.Total, g.More)
	}
}

// Давность без времени последнего контакта не выдумывается: у машины, которая
// не отчитывалась ни разу, его нет, и «53 года назад» хуже пустоты.
func TestHumanAgo(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"мусор":               "",
		time.Now().UTC().Add(-30 * time.Second).Format("2006-01-02 15:04:05"): "только что",
		time.Now().UTC().Add(-42 * time.Minute).Format("2006-01-02 15:04:05"): "42 мин",
		time.Now().UTC().Add(-5 * time.Hour).Format("2006-01-02 15:04:05"):    "5 ч",
		time.Now().UTC().Add(-50 * time.Hour).Format("2006-01-02 15:04:05"):   "2 дн",
	}
	for in, want := range cases {
		if got := humanAgo(in); got != want {
			t.Errorf("humanAgo(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

// Отключённые проверки в сводку не попадают — иначе она заполнится тем,
// что администратор осознанно выключил.
func TestIssuesSkipsDisabled(t *testing.T) {
	a := newTestApp(t)
	a.DB.Exec(`INSERT INTO service_checks (name, type, target, enabled, last_status)
		VALUES ('Старый','tcp','1.2.3.4:80',0,'down')`)
	a.DB.Exec(`INSERT INTO snmp_devices (name, ip, kind, enabled, last_status, supply_alert)
		VALUES ('Списанный','192.168.1.90','printer',0,'down',1)`)
	if got := a.issueGroups(); len(got) != 0 {
		t.Fatalf("отключённое не должно попадать в сводку: %+v", got)
	}
}

// Здоровые диски в сводку не попадают, а оценка совпадает со страницей дисков.
func TestDiskIssuesUsesSameVerdict(t *testing.T) {
	a := newTestApp(t)
	a.DB.Exec(`INSERT INTO devices (id, hostname) VALUES (1,'WS-1')`)
	a.DB.Exec(`INSERT INTO disks (device_id, model, serial, health, wear_pct) VALUES (1,'A','1','ok',10)`)
	a.DB.Exec(`INSERT INTO disks (device_id, model, serial, health, wear_pct) VALUES (1,'B','2','ok',85)`)
	a.DB.Exec(`INSERT INTO disks (device_id, model, serial, health, wear_pct) VALUES (1,'C','3','unhealthy',5)`)

	got := map[string]int{}
	for _, g := range a.diskGroups() {
		got[g.Cause] = g.Total
	}
	if got["Диски: ожидается отказ"] != 1 || got["Диски с предупреждением SMART"] != 1 {
		t.Fatalf("получено %+v, ожидалось по одному в каждой группе", got)
	}
}
