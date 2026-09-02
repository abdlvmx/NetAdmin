package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

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
		Issues: []dashIssue{
			{Label: "Сервисы не отвечают", Count: 2, Href: "/monitoring", Crit: true},
			{Label: "Расходники и батареи на исходе", Count: 1, Href: "/snmp"},
		},
	})
	body := rec.Body.String()
	for _, want := range []string{"Требует внимания", "Сервисы не отвечают", `href="/monitoring"`,
		"Расходники и батареи на исходе", `href="/snmp"`} {
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

// issues собирает проблемы из всех разделов, а не только из устройств.
func TestIssuesCollectsAllSources(t *testing.T) {
	a := newTestApp(t)
	a.DB.Exec(`INSERT INTO service_checks (name, type, target, enabled, last_status)
		VALUES ('1С','tcp','192.168.1.5:1541',1,'down')`)
	a.DB.Exec(`INSERT INTO snmp_devices (name, ip, kind, enabled, last_status, supply_alert)
		VALUES ('Принтер','192.168.1.50','printer',1,'up',1)`)
	a.DB.Exec(`INSERT INTO snmp_devices (name, ip, kind, enabled, last_status)
		VALUES ('ИБП','192.168.1.7','ups',1,'down')`)
	a.DB.Exec(`INSERT INTO disks (device_id, model, serial, health, predict_fail)
		VALUES (1,'ST1000','X1','ok',1)`)

	got := map[string]int{}
	for _, is := range a.issues(3) {
		got[is.Label] = is.Count
	}
	for label, want := range map[string]int{
		"Устройства: офлайн или перегрузка": 3,
		"Сервисы не отвечают":               1,
		"SNMP-устройства недоступны":        1,
		"Расходники и батареи на исходе":    1,
		"Диски: ожидается отказ":            1,
	} {
		if got[label] != want {
			t.Errorf("%q: получено %d, ожидалось %d", label, got[label], want)
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
	if got := a.issues(0); len(got) != 0 {
		t.Fatalf("отключённое не должно попадать в сводку: %+v", got)
	}
}

// Здоровые диски в сводку не попадают, а оценка совпадает со страницей дисков.
func TestDiskIssuesUsesSameVerdict(t *testing.T) {
	a := newTestApp(t)
	a.DB.Exec(`INSERT INTO disks (device_id, model, serial, health, wear_pct) VALUES (1,'A','1','ok',10)`)
	a.DB.Exec(`INSERT INTO disks (device_id, model, serial, health, wear_pct) VALUES (1,'B','2','ok',85)`)
	a.DB.Exec(`INSERT INTO disks (device_id, model, serial, health, wear_pct) VALUES (1,'C','3','unhealthy',5)`)
	crit, warn := a.diskIssues()
	if crit != 1 || warn != 1 {
		t.Fatalf("получено crit=%d warn=%d, ожидалось 1 и 1", crit, warn)
	}
}
