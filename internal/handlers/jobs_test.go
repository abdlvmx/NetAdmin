package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"netadmin/internal/db"
	"netadmin/internal/deviceaccess"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func queueTestJob(t *testing.T, a *App, ids []int64, spec taskSpec) queuedJob {
	t.Helper()
	j, err := a.enqueueJob(context.Background(), ids, spec, 0)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func jobRequest(t *testing.T, a *App, cookie *http.Cookie, job int64, action string, values url.Values) int {
	t.Helper()
	w := mfaRequest(a, "POST", fmt.Sprintf("/jobs/%d/%s", job, action), values, cookie)
	return w.Code
}
func TestJobCreationIsAtomicAndCombinesBatchTargets(t *testing.T) {
	a, limited, _, _, _, own, other := scopeFixture(t)
	spec := taskSpec{Kind: "command", Payload: "ipconfig", Label: "Сетевая конфигурация"}
	if _, err := a.enqueueJob(context.Background(), []int64{own, 999999}, spec, 0); err == nil {
		t.Fatal("missing target accepted")
	}
	var n int
	a.DB.QueryRow("SELECT COUNT(*) FROM agent_jobs").Scan(&n)
	if n != 0 {
		t.Fatal("failed batch left a job")
	}
	a.DB.QueryRow("SELECT COUNT(*) FROM agent_tasks").Scan(&n)
	if n != 0 {
		t.Fatal("failed batch partly enqueued")
	}
	j := queueTestJob(t, a, []int64{own, own, other}, spec)
	if len(j.Tasks) != 2 {
		t.Fatal("duplicate device created duplicate execution")
	}
	a.DB.QueryRow("SELECT COUNT(*) FROM agent_jobs").Scan(&n)
	if n != 1 {
		t.Fatal("batch split into separate jobs")
	}
	w := mfaRequest(a, "GET", fmt.Sprintf("/api/jobs/%d", j.ID), nil, limited)
	var response struct {
		Job   jobSummary
		Tasks []jobTask
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != 200 || response.Job.Total != 1 || len(response.Tasks) != 1 || response.Tasks[0].DeviceID != own {
		t.Fatalf("scoped totals: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "PRIVATE-B") || strings.Contains(w.Body.String(), "Payload") {
		t.Fatal("job API exposed foreign data or payload")
	}
}
func TestJobMigrationPreservesDeliveryAndIsIdempotent(t *testing.T) {
	a := newTestApp(t)
	for _, id := range []int64{101, 102} {
		if _, err := a.DB.Exec(`INSERT INTO agent_tasks(id,device_id,kind,payload,label,status,created_at,execution_key,task_protocol,cancel_requested,result) VALUES(?,1,'command','ipconfig','old','running','2026-10-01 00:00:00','execution-key',2,1,'kept')`, id); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := db.InitSchema(a.DB); err != nil {
			t.Fatal(err)
		}
	}
	var jobs, distinct int
	a.DB.QueryRow("SELECT COUNT(*),COUNT(DISTINCT id) FROM agent_jobs").Scan(&jobs, &distinct)
	if jobs != 2 || distinct != 2 {
		t.Fatal("legacy tasks guessed as a batch or backfilled twice")
	}
	var status, key, result string
	var protocol, cancel int
	var job int64
	if err := a.DB.QueryRow("SELECT status,execution_key,result,task_protocol,cancel_requested,job_id FROM agent_tasks WHERE id=101").Scan(&status, &key, &result, &protocol, &cancel, &job); err != nil {
		t.Fatal(err)
	}
	if status != "running" || key != "execution-key" || result != "kept" || protocol != 2 || cancel != 1 || job <= 0 {
		t.Fatal("migration changed delivery state")
	}
}
func TestJobsFilterBeforePaginationAndDoNotSearchHiddenDevices(t *testing.T) {
	a, limited, full, _, _, own, other := scopeFixture(t)
	spec := taskSpec{Kind: "command", Payload: "ipconfig", Label: "Own operation"}
	visible := queueTestJob(t, a, []int64{own}, spec)
	spec.Label = "Foreign operation"
	for i := 0; i < 55; i++ {
		queueTestJob(t, a, []int64{other}, spec)
	}
	w := mfaRequest(a, "GET", "/jobs", nil, limited)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Own operation") || strings.Contains(w.Body.String(), "Foreign operation") {
		t.Fatal("hidden jobs displaced visible job before limit")
	}
	for _, path := range []string{"/jobs?q=PRIVATE-B", "/jobs?status=failed"} {
		w = mfaRequest(a, "GET", path, nil, limited)
		if w.Code != 200 || strings.Contains(w.Body.String(), "Own operation") || strings.Contains(w.Body.String(), "Foreign operation") {
			t.Fatalf("filter leak: %s", path)
		}
	}
	w = mfaRequest(a, "GET", "/jobs", nil, full)
	if !strings.Contains(w.Body.String(), "Более ранние задания") {
		t.Fatal("missing pagination")
	}
	var n int
	a.DB.QueryRow("SELECT COUNT(*) FROM agent_jobs").Scan(&n)
	if n != 56 {
		t.Fatal("jobs unexpectedly mutated")
	}
	w = mfaRequest(a, "GET", fmt.Sprintf("/jobs/%d", visible.ID), nil, limited)
	if w.Code != 200 {
		t.Fatal("own job unavailable")
	}
}
func TestCancelJobRespectsScopeAndProtocol(t *testing.T) {
	a, limited, full, _, _, own, other := scopeFixture(t)
	j := queueTestJob(t, a, []int64{own, other}, taskSpec{Kind: "command", Payload: "ipconfig", Label: "Cancel batch"})
	if got := jobRequest(t, a, limited, j.ID, "cancel", url.Values{}); got != 400 {
		t.Fatal("cancellation did not require confirmation")
	}
	if got := jobRequest(t, a, limited, j.ID, "cancel", url.Values{"confirm": {"1"}}); got != 303 {
		t.Fatalf("cancel failed: %d", got)
	}
	var ownStatus, otherStatus string
	a.DB.QueryRow("SELECT status FROM agent_tasks WHERE id=?", j.Tasks[0]).Scan(&ownStatus)
	a.DB.QueryRow("SELECT status FROM agent_tasks WHERE id=?", j.Tasks[1]).Scan(&otherStatus)
	if ownStatus != "cancelled" || otherStatus != "pending" {
		t.Fatal("scoped cancellation changed hidden device")
	}
	if got := jobRequest(t, a, full, j.ID, "cancel", url.Values{"confirm": {"1"}}); got != 303 {
		t.Fatal("full cancellation failed")
	}
	for _, protocol := range []int{1, 2} {
		one := queueTestJob(t, a, []int64{own}, taskSpec{Kind: "check", Label: "Check"})
		a.DB.Exec("UPDATE agent_tasks SET status='sent',task_protocol=? WHERE id=?", protocol, one.Tasks[0])
		got := jobRequest(t, a, full, one.ID, "cancel", url.Values{"confirm": {"1"}})
		var cancelled int
		a.DB.QueryRow("SELECT cancel_requested FROM agent_tasks WHERE id=?", one.Tasks[0]).Scan(&cancelled)
		if protocol == 1 && (got != 409 || cancelled != 0) {
			t.Fatal("legacy sent task claimed cancelled")
		}
		if protocol == 2 && (got != 303 || cancelled != 1) {
			t.Fatal("protocol 2 missing cancellation request")
		}
	}
}
func TestRetryOnlyFailedTasksAndKeepsOriginalResult(t *testing.T) {
	a, limited, full, _, _, own, other := scopeFixture(t)
	j := queueTestJob(t, a, []int64{own, other}, taskSpec{Kind: "command", Payload: "ipconfig", Label: "Retry batch"})
	a.DB.Exec("UPDATE agent_tasks SET status='failed',result='Original error',exit_code=7 WHERE job_id=?", j.ID)
	form := url.Values{"confirm": {"1"}, "task": {fmt.Sprint(j.Tasks[0]), fmt.Sprint(j.Tasks[1])}}
	if got := jobRequest(t, a, limited, j.ID, "retry", form); got != 403 {
		t.Fatalf("mixed retry accepted: %d", got)
	}
	var n int
	a.DB.QueryRow("SELECT COUNT(*) FROM agent_jobs").Scan(&n)
	if n != 1 {
		t.Fatal("mixed retry partly queued")
	}
	form.Set("task", fmt.Sprint(j.Tasks[0]))
	form.Del("confirm")
	if got := jobRequest(t, a, limited, j.ID, "retry", form); got != 400 {
		t.Fatal("retry omitted confirmation")
	}
	form.Set("confirm", "1")
	if got := jobRequest(t, a, limited, j.ID, "retry", form); got != 303 {
		t.Fatalf("retry failed: %d", got)
	}
	if got := jobRequest(t, a, limited, j.ID, "retry", form); got != 409 {
		t.Fatal("replayed retry created another attempt")
	}
	var source, status, result string
	var code int
	var child, parent, device, retryOf int64
	a.DB.QueryRow("SELECT status,result,exit_code FROM agent_tasks WHERE id=?", j.Tasks[0]).Scan(&status, &result, &code)
	if status != "failed" || result != "Original error" || code != 7 {
		t.Fatal("retry overwrote original failure")
	}
	a.DB.QueryRow("SELECT job_id,device_id,retry_of,payload FROM agent_tasks WHERE retry_of=?", j.Tasks[0]).Scan(&child, &device, &retryOf, &source)
	a.DB.QueryRow("SELECT parent_id FROM agent_jobs WHERE id=?", child).Scan(&parent)
	if child == j.ID || parent != j.ID || device != own || retryOf != j.Tasks[0] || source != "ipconfig" {
		t.Fatal("retry lineage or target incorrect")
	}
	a.DB.Exec("UPDATE agent_tasks SET status='done' WHERE id=?", j.Tasks[1])
	form.Set("task", fmt.Sprint(j.Tasks[1]))
	if got := jobRequest(t, a, full, j.ID, "retry", form); got != 409 {
		t.Fatal("successful task retried")
	}
}
func TestConcurrentRetryCreatesAtMostOneExecution(t *testing.T) {
	a, _, full, _, _, own, _ := scopeFixture(t)
	j := queueTestJob(t, a, []int64{own}, taskSpec{Kind: "command", Payload: "ipconfig", Label: "Concurrent retry"})
	a.DB.Exec("UPDATE agent_tasks SET status='failed' WHERE job_id=?", j.ID)
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- jobRequest(t, a, full, j.ID, "retry", url.Values{"confirm": {"1"}, "task": {fmt.Sprint(j.Tasks[0])}})
		}()
	}
	wg.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 303 {
			success++
		} else if code != 409 && code != 503 {
			t.Fatalf("unexpected retry response: %d", code)
		}
	}
	var n int
	a.DB.QueryRow("SELECT COUNT(*) FROM agent_tasks WHERE retry_of=?", j.Tasks[0]).Scan(&n)
	if success != 1 || n != 1 {
		t.Fatalf("duplicate retry: successes %d tasks %d", success, n)
	}
}
func TestJobPermissionsRevocationAndEscapedResult(t *testing.T) {
	a, limited, _, user, group, own, other := scopeFixture(t)
	viewer := sessionFor(t, a, "job-viewer", "viewer")
	j := queueTestJob(t, a, []int64{own}, taskSpec{Kind: "command", Payload: "ipconfig", Label: "Read job"})
	a.DB.Exec("UPDATE agent_tasks SET status='failed',result=? WHERE job_id=?", `<script>alert("job-pwn")</script>`, j.ID)
	for _, action := range []string{"cancel", "retry"} {
		if got := jobRequest(t, a, viewer, j.ID, action, url.Values{"confirm": {"1"}, "task": {fmt.Sprint(j.Tasks[0])}}); got != 403 {
			t.Fatal("viewer mutated job")
		}
	}
	w := mfaRequest(a, "GET", fmt.Sprintf("/jobs/%d/tasks/%d", j.ID, j.Tasks[0]), nil, limited)
	if w.Code != 200 || strings.Contains(w.Body.String(), `<script>alert("job-pwn")</script>`) || !strings.Contains(w.Body.String(), "&lt;script&gt;") {
		t.Fatal("result not escaped")
	}
	foreign := queueTestJob(t, a, []int64{other}, taskSpec{Kind: "command", Payload: "ipconfig", Label: "Hidden"})
	for _, path := range []string{fmt.Sprintf("/jobs/%d", foreign.ID), fmt.Sprintf("/api/jobs/%d", foreign.ID), fmt.Sprintf("/jobs/%d/tasks/%d", j.ID, foreign.Tasks[0])} {
		if w := mfaRequest(a, "GET", path, nil, limited); w.Code != 404 {
			t.Fatalf("foreign job access: %s %d", path, w.Code)
		}
	}
	if err := deviceaccess.SetUserScope(context.Background(), a.DB, user, deviceaccess.Scope{Mode: "groups", Revision: 1}, 0); err != nil {
		t.Fatal(err)
	}
	if w := mfaRequest(a, "GET", fmt.Sprintf("/jobs/%d", j.ID), nil, limited); w.Code != 404 {
		t.Fatal("revoked session still accessed job")
	}
	if got := jobRequest(t, a, limited, j.ID, "retry", url.Values{"confirm": {"1"}, "task": {fmt.Sprint(j.Tasks[0])}}); got != 404 {
		t.Fatal("revoked access still retried")
	}
	_ = group
}
func TestRetryPackageRequiresAdminAndUnchangedAvailableFile(t *testing.T) {
	a, _, operator, _, _, own, _ := scopeFixture(t)
	admin := sessionFor(t, a, "job-admin", "admin")
	if err := os.WriteFile(filepath.Join(packagesDir(), "pkg.exe"), []byte("isolated dummy package"), 0600); err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte("isolated dummy package")))
	a.DB.Exec("INSERT INTO packages(id,name,kind,filename,sha256,install_args) VALUES(1,'Test','exe','pkg.exe',?,'/S')", sum)
	payload, _ := json.Marshal(installPayload{ID: 1, Name: "Test", Kind: "exe", Filename: "pkg.exe", SHA256: sum, Args: "/S"})
	j := queueTestJob(t, a, []int64{own}, taskSpec{Kind: "install", Payload: string(payload), Label: "Install", PackageID: 1})
	a.DB.Exec("UPDATE agent_tasks SET status='failed' WHERE job_id=?", j.ID)
	form := url.Values{"confirm": {"1"}, "task": {strconv.FormatInt(j.Tasks[0], 10)}}
	if got := jobRequest(t, a, operator, j.ID, "retry", form); got != 403 {
		t.Fatal("operator repeated installation")
	}
	a.DB.Exec("UPDATE packages SET install_args='/changed' WHERE id=1")
	if got := jobRequest(t, a, admin, j.ID, "retry", form); got != 409 {
		t.Fatal("changed package repeated")
	}
	a.DB.Exec("UPDATE packages SET install_args='/S' WHERE id=1")
	if err := os.Remove(filepath.Join(packagesDir(), "pkg.exe")); err != nil {
		t.Fatal(err)
	}
	if got := jobRequest(t, a, admin, j.ID, "retry", form); got != 409 {
		t.Fatal("missing file repeated")
	}
	if err := os.WriteFile(filepath.Join(packagesDir(), "pkg.exe"), []byte("changed file without changed database"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := jobRequest(t, a, admin, j.ID, "retry", form); got != 409 {
		t.Fatal("changed file repeated")
	}
	if err := os.WriteFile(filepath.Join(packagesDir(), "pkg.exe"), []byte("isolated dummy package"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := jobRequest(t, a, admin, j.ID, "retry", form); got != 303 {
		t.Fatalf("valid package failed: %d", got)
	}
}
