package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// searchResult — форма ответа /api/search.
type searchResult struct {
	Groups []searchGroup `json:"groups"`
}

func doSearch(t *testing.T, a *App, q string) searchResult {
	t.Helper()
	rec := adminRequest(t, a, "GET", "http://192.168.1.64:8765/api/search?q="+url.QueryEscape(q))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var res searchResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("разбор ответа: %v (%s)", err, rec.Body.String())
	}
	return res
}

func seedSearchData(t *testing.T, a *App) {
	t.Helper()
	a.DB.Exec("INSERT INTO departments (id,name) VALUES (1,'Бухгалтерия')")
	a.DB.Exec(`INSERT INTO employees (id,full_name,position,department_id,email)
		VALUES (1,'Смирнова Ольга Петровна','Главный бухгалтер',1,'olga@firma.local')`)
	a.DB.Exec(`INSERT INTO devices (id,hostname,ip_address,mac_address,location,employee_id,status)
		VALUES (1,'BUH-01','192.168.1.11','AA:BB:CC:00:00:01','каб. 201',1,'online')`)
	a.DB.Exec(`INSERT INTO devices (id,hostname,ip_address,status)
		VALUES (2,'KADR-01','192.168.1.21','offline')`)
	a.DB.Exec(`INSERT INTO software (device_id,name) VALUES (1,'uTorrent 3.6'),(2,'uTorrent 3.6')`)
	a.DB.Exec(`INSERT INTO tickets (id,code,title,reporter_name,status)
		VALUES (1,'AB12CD','Не печатает принтер','Смирнова Ольга','new')`)
}

// Поиск отвечает на вопрос, не требуя знать, в каком разделе искать.
func TestSearchAcrossSections(t *testing.T) {
	a := newTestApp(t)
	seedSearchData(t, a)

	// по имени машины
	res := doSearch(t, a, "BUH")
	if len(res.Groups) == 0 || res.Groups[0].Title != "Устройства" {
		t.Fatalf("устройство не найдено: %+v", res.Groups)
	}
	if res.Groups[0].Items[0].Href != "/devices/1" {
		t.Errorf("ссылка ведёт не в карточку: %q", res.Groups[0].Items[0].Href)
	}

	// по программе — с указанием, где установлена
	res = doSearch(t, a, "utorrent")
	var sw *searchGroup
	for i := range res.Groups {
		if res.Groups[i].Title == "Программы" {
			sw = &res.Groups[i]
		}
	}
	if sw == nil {
		t.Fatalf("программа не найдена: %+v", res.Groups)
	}
	if !strings.Contains(sw.Items[0].Sub, "на 2 ПК") {
		t.Errorf("не показано, на скольких ПК установлено: %q", sw.Items[0].Sub)
	}

	// по человеку
	if res := doSearch(t, a, "Смирнова"); len(res.Groups) == 0 {
		t.Error("сотрудник не найден")
	}
	// по заявке
	if res := doSearch(t, a, "AB12CD"); len(res.Groups) == 0 {
		t.Error("заявка не найдена")
	}
	// по кабинету — устройство находится по расположению
	if res := doSearch(t, a, "каб. 201"); len(res.Groups) == 0 {
		t.Error("устройство не найдено по расположению")
	}
	// по владельцу — устройство находится через сотрудника
	res = doSearch(t, a, "Ольга Петровна")
	found := false
	for _, g := range res.Groups {
		if g.Title == "Устройства" {
			found = true
		}
	}
	if !found {
		t.Error("устройство не найдено по имени владельца")
	}
}

// Слишком короткий запрос совпал бы почти со всем — выдачи быть не должно.
func TestSearchIgnoresShortQuery(t *testing.T) {
	a := newTestApp(t)
	seedSearchData(t, a)
	for _, q := range []string{"", "a", " "} {
		if res := doSearch(t, a, q); len(res.Groups) != 0 {
			t.Errorf("запрос %q дал выдачу: %+v", q, res.Groups)
		}
	}
}

// Поиск идёт по данным организации, поэтому доступен только вошедшим.
func TestSearchRequiresLogin(t *testing.T) {
	a := newTestApp(t)
	req := mustRequest("GET", "http://192.168.1.64:8765/api/search?q=BUH")
	rec := recorder()
	a.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("аноним получил %d вместо 403", rec.Code)
	}
}

func mustRequest(method, url string) *http.Request {
	req, _ := http.NewRequest(method, url, nil)
	req.RemoteAddr = "127.0.0.1:40000"
	return req
}

func recorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }
