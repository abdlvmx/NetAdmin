package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/url"
	"netadmin/internal/auth"
	"netadmin/internal/deviceaccess"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func scopeFixture(t *testing.T) (*App, *http.Cookie, *http.Cookie, int64, int64, int64, int64) {
	t.Helper()
	a := newTestApp(t)
	limited, full := sessionFor(t, a, "scoped-operator", "user"), sessionFor(t, a, "full-operator", "user")
	var user int64
	a.DB.QueryRow("SELECT id FROM users WHERE username='scoped-operator'").Scan(&user)
	insert := func(name, ip string, cpu int) int64 {
		result, err := a.DB.Exec("INSERT INTO devices(hostname,ip_address,agent_token,cpu_usage,status,location) VALUES(?,?,'fake-agent',?,'online',?)", name, ip, cpu, name)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := result.LastInsertId()
		return id
	}
	own, other := insert("PRIVATE-A", "192.0.2.10", 10), insert("PRIVATE-B", "192.0.2.20", 90)
	for _, id := range []int64{own, other} {
		if _, err := a.DB.Exec("INSERT INTO metrics_history(device_id,ts,cpu_usage,ram_usage,disk_usage) SELECT id,datetime('now'),cpu_usage,20,30 FROM devices WHERE id=?", id); err != nil {
			t.Fatal(err)
		}
	}
	group, err := deviceaccess.CreateGroup(context.Background(), a.DB, "Назначенные ПК", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = deviceaccess.UpdateGroup(context.Background(), a.DB, deviceaccess.Group{ID: group, Name: "Назначенные ПК", Revision: 1}, []int64{own}, 0); err != nil {
		t.Fatal(err)
	}
	if err = deviceaccess.SetUserScope(context.Background(), a.DB, user, deviceaccess.Scope{Mode: "groups", GroupIDs: []int64{group}}, 0); err != nil {
		t.Fatal(err)
	}
	return a, limited, full, user, group, own, other
}

func TestDeviceScopeFiltersListsExportsSearchAndFleetMetrics(t *testing.T) {
	a, limited, full, _, _, own, other := scopeFixture(t)
	for _, path := range []string{"/devices", "/devices/export", "/dashboard", "/commands", "/api/search?q=PRIVATE", "/disk-health", "/capacity"} {
		w := mfaRequest(a, "GET", path, nil, limited)
		if w.Code != 200 || strings.Contains(w.Body.String(), "PRIVATE-B") {
			t.Fatalf("scope leak on %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	w := mfaRequest(a, "GET", "/devices", nil, full)
	if !strings.Contains(w.Body.String(), "PRIVATE-A") || !strings.Contains(w.Body.String(), "PRIVATE-B") {
		t.Fatal("scoped request contaminated unrestricted app")
	}
	if a.scope != nil {
		t.Fatal("shared app retained a request scope")
	}
	w = mfaRequest(a, "GET", "/api/devices/status", nil, limited)
	var status struct {
		Devices []struct {
			ID int64 `json:"id"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || len(status.Devices) != 1 || status.Devices[0].ID != own {
		t.Fatal("status API exposed other IDs")
	}
	w = mfaRequest(a, "GET", "/api/metrics/fleet?hours=1", nil, limited)
	var metrics struct {
		Points []metricPoint `json:"points"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &metrics); err != nil || len(metrics.Points) != 1 || metrics.Points[0].CPU != 10 {
		t.Fatalf("fleet metrics not filtered: %s", w.Body.String())
	}
	for _, path := range []string{"/employees", "/tickets", "/licenses", "/network-map", "/api/network-map", "/network-changes", "/snmp", "/monitoring", "/discovery"} {
		if w := mfaRequest(a, "GET", path, nil, limited); w.Code != 403 {
			t.Fatalf("organization-wide route exposed: %s %d", path, w.Code)
		}
	}
	for _, route := range routesFromSource(t) {
		if !strings.Contains(route.pattern, "/devices/{id}") {
			continue
		}
		path := requestPath(route.pattern)
		path = strings.Replace(path, "/devices/1", "/devices/"+strconv.FormatInt(other, 10), 1)
		w := mfaRequest(a, route.method, path, nil, limited)
		if w.Code != 404 {
			t.Errorf("direct device route %s accepted foreign ID: %d", route.pattern, w.Code)
		}
	}
}

func TestDeviceScopeMixedOperationsHaveNoPartialEffectsAndAllMeansAssigned(t *testing.T) {
	a, limited, _, user, _, own, other := scopeFixture(t)
	selected := []string{strconv.FormatInt(own, 10), strconv.FormatInt(other, 10)}
	w := mfaRequest(a, "POST", "/commands/run", url.Values{"cmd": {"ipconfig"}, "device": selected}, limited)
	if w.Code != 403 {
		t.Fatalf("mixed command accepted: %d", w.Code)
	}
	var tasks int
	a.DB.QueryRow("SELECT COUNT(*) FROM agent_tasks").Scan(&tasks)
	if tasks != 0 {
		t.Fatal("mixed selection queued a partial command")
	}
	w = mfaRequest(a, "POST", "/devices/bulk", url.Values{"action": {"location"}, "value": {"Changed"}, "device": selected}, limited)
	if w.Code != 403 {
		t.Fatal("mixed bulk update accepted")
	}
	var location string
	a.DB.QueryRow("SELECT location FROM devices WHERE id=?", own).Scan(&location)
	if location != "PRIVATE-A" {
		t.Fatal("mixed bulk update partially changed own device")
	}
	w = mfaRequest(a, "POST", "/commands/run", url.Values{"cmd": {"ipconfig"}, "all": {"1"}}, limited)
	if w.Code != 303 {
		t.Fatalf("assigned fleet command failed: %d %s", w.Code, w.Body.String())
	}
	var target, creator int64
	a.DB.QueryRow("SELECT device_id,created_by FROM agent_tasks").Scan(&target, &creator)
	a.DB.QueryRow("SELECT COUNT(*) FROM agent_tasks").Scan(&tasks)
	if tasks != 1 || target != own || creator != user {
		t.Fatal("all command included other groups")
	}
	w = mfaRequest(a, "POST", "/devices/"+strconv.FormatInt(own, 10)+"/update", url.Values{"ip_address": {"192.0.2.20"}}, limited)
	if w.Code != 403 {
		t.Fatal("limited operator changed diagnostic target address")
	}
}

func TestDeviceScopeChangesApplyToExistingSessionAndEmptyGroupsDenyAll(t *testing.T) {
	a, limited, _, user, group, _, _ := scopeFixture(t)
	if err := deviceaccess.DeleteGroup(context.Background(), a.DB, group, 2, 0); err != nil {
		t.Fatal(err)
	}
	w := mfaRequest(a, "GET", "/devices", nil, limited)
	if w.Code != 200 || strings.Contains(w.Body.String(), "PRIVATE-A") || strings.Contains(w.Body.String(), "PRIVATE-B") {
		t.Fatal("deleted group gave default full access")
	}
	scope, err := deviceaccess.UserScope(context.Background(), a.DB, user)
	if err != nil || scope.Mode != "groups" {
		t.Fatal("scope mode lost")
	}
	if err = deviceaccess.SetUserScope(context.Background(), a.DB, user, deviceaccess.Scope{Mode: "all", Revision: scope.Revision}, 0); err != nil {
		t.Fatal(err)
	}
	w = mfaRequest(a, "GET", "/devices", nil, limited)
	if !strings.Contains(w.Body.String(), "PRIVATE-B") {
		t.Fatal("grant change did not apply to existing session")
	}
}

func TestConcurrentScopedAndUnrestrictedRequestsDoNotShareScope(t *testing.T) {
	a, limited, full, _, _, _, _ := scopeFixture(t)
	var wg sync.WaitGroup
	failures := make(chan string, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cookie := limited
			if i%2 == 1 {
				cookie = full
			}
			w := mfaRequest(a, "GET", "/devices", nil, cookie)
			seen := strings.Contains(w.Body.String(), "PRIVATE-B")
			if w.Code != 200 || seen != (i%2 == 1) {
				failures <- fmt.Sprintf("request %d: %d foreign=%t", i, w.Code, seen)
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

func TestNamedRoutesUseDeviceScopeDispatcher(t *testing.T) {
	for _, source := range []string{"app.go", "securityevents.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || method.Sel.Name != "HandleFunc" {
				return true
			}
			if route, ok := call.Args[0].(*ast.BasicLit); ok && route.Value == `"GET /favicon.ico"` {
				return true // Static icon has no account or inventory data.
			}
			if _, inline := call.Args[1].(*ast.FuncLit); inline {
				return true
			}
			wrapper, ok := call.Args[1].(*ast.CallExpr)
			if !ok {
				t.Error("named route missing scope dispatcher")
				return true
			}
			selector, ok := wrapper.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "deviceScoped" {
				t.Error("route uses unknown scope dispatcher")
			}
			return true
		})
	}
}

func TestNewUserScopeIsSafeAndInvalidGrantsRollBackCreation(t *testing.T) {
	a := newTestApp(t)
	admin := sessionFor(t, a, "scope-admin", "admin")
	for _, invalid := range []url.Values{
		{"device_access": {"groups"}, "group": {"999999"}},
		{"device_access": {"unknown"}},
	} {
		invalid.Set("username", "invalid-scope-user")
		invalid.Set("role", "user")
		invalid.Set("password", "Parol12345")
		w := mfaRequest(a, "POST", "/users/create", invalid, admin)
		if w.Code != 400 {
			t.Fatalf("invalid grant accepted: %d", w.Code)
		}
		var count int
		a.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username='invalid-scope-user'").Scan(&count)
		if count != 0 {
			t.Fatal("failed creation left an account behind")
		}
	}
	w := mfaRequest(a, "POST", "/users/create", url.Values{"username": {"new-scope-user"}, "role": {"user"}, "password": {"Parol12345"}}, admin)
	if w.Code != 303 {
		t.Fatalf("create failed: %d %s", w.Code, w.Body.String())
	}
	var id int64
	a.DB.QueryRow("SELECT id FROM users WHERE username='new-scope-user'").Scan(&id)
	scope, err := deviceaccess.UserScope(context.Background(), a.DB, id)
	if err != nil || scope.Mode != "groups" || len(scope.GroupIDs) != 0 {
		t.Fatal("new account defaulted to full access")
	}
}

func TestScopeUnionAndRelatedObjectsDoNotExpandAccess(t *testing.T) {
	a, limited, _, user, group, own, other := scopeFixture(t)
	ctx := context.Background()
	second, err := deviceaccess.CreateGroup(ctx, a.DB, "Вторая группа", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = deviceaccess.UpdateGroup(ctx, a.DB, deviceaccess.Group{ID: second, Name: "Вторая группа", Revision: 1}, []int64{own, other}, 0); err != nil {
		t.Fatal(err)
	}
	if err = deviceaccess.SetUserScope(ctx, a.DB, user, deviceaccess.Scope{Mode: "groups", Revision: 1, GroupIDs: []int64{group, second}}, 0); err != nil {
		t.Fatal(err)
	}
	w := mfaRequest(a, "GET", "/devices", nil, limited)
	if !strings.Contains(w.Body.String(), "PRIVATE-A") || !strings.Contains(w.Body.String(), "PRIVATE-B") {
		t.Fatal("grants did not combine devices from both groups")
	}
	if err = deviceaccess.DeleteGroup(ctx, a.DB, second, 2, 0); err != nil {
		t.Fatal(err)
	}
	w = mfaRequest(a, "GET", "/devices", nil, limited)
	if !strings.Contains(w.Body.String(), "PRIVATE-A") || strings.Contains(w.Body.String(), "PRIVATE-B") {
		t.Fatal("overlapping grants did not retain only the first group")
	}
	result, err := a.DB.Exec("INSERT INTO employees(full_name) VALUES('FOREIGN-EMPLOYEE')")
	if err != nil {
		t.Fatal(err)
	}
	employee, _ := result.LastInsertId()
	if _, err = a.DB.Exec("UPDATE devices SET employee_id=? WHERE id=?", employee, other); err != nil {
		t.Fatal(err)
	}
	values := url.Values{"employee_id": {strconv.FormatInt(employee, 10)}}
	w = mfaRequest(a, "POST", fmt.Sprintf("/devices/%d/update", own), values, limited)
	if w.Code != 403 {
		t.Fatal("foreign employee linked through guessed ID")
	}
	w = mfaRequest(a, "POST", "/devices/bulk", url.Values{"action": {"employee"}, "value": {strconv.FormatInt(employee, 10)}, "device": {strconv.FormatInt(own, 10)}}, limited)
	if w.Code != 403 {
		t.Fatal("bulk linked foreign employee")
	}
	w = mfaRequest(a, "POST", "/api/ping", url.Values{"ip": {"192.0.2.20"}}, limited)
	if w.Code != 403 {
		t.Fatalf("foreign ping accepted: %d", w.Code)
	}
	for _, route := range []string{"/commands/run", "/devices/bulk"} {
		w = mfaRequest(a, "POST", route, url.Values{"cmd": {"ipconfig"}, "action": {"location"}, "value": {"changed"}, "device": {strconv.FormatInt(own, 10), "bad"}}, limited)
		if w.Code != 400 {
			t.Fatalf("malformed selection accepted on %s: %d", route, w.Code)
		}
	}
	result, err = a.DB.Exec("INSERT INTO agent_tasks(device_id,kind,payload,label,created_by) VALUES(?,'command','ipconfig','foreign',?)", other, user)
	if err != nil {
		t.Fatal(err)
	}
	task, _ := result.LastInsertId()
	if w = mfaRequest(a, "POST", fmt.Sprintf("/api/tasks/%d/cancel", task), nil, limited); w.Code != 404 {
		t.Fatal("foreign task cancellation exposed")
	}
	// Even a receiver bound before policy removal cannot fall back to global data.
	a.scope = &auth.User{ID: user, DeviceRestricted: true}
	if _, err = a.DB.Exec("DELETE FROM user_device_access WHERE user_id=?", user); err != nil {
		t.Fatal(err)
	}
	if a.scopedDeviceAllowed(own) {
		t.Fatal("bound request gained full access after policy removal")
	}
}
