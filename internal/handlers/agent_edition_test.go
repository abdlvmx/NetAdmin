package handlers

import (
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"netadmin/internal/edition"
)

func wrongAgentEdition() string {
	if edition.ID == "standard" {
		return "events"
	}
	return "standard"
}

func TestWrongUploadedAgentCannotOverrideEmbeddedEdition(t *testing.T) {
	a := newTestApp(t)
	withEmbeddedAgent(t, "embedded", "sha")
	addAgentBuild(t, a, "agent.exe", "wrong-edition", "sha-wrong")
	readAgentEdition = func(string) (string, error) { return wrongAgentEdition(), nil }
	b, ok := a.latestAgentBuild()
	if !ok || !b.Embedded {
		t.Fatal("wrong edition offered to new devices")
	}
}

func TestUnknownUploadedAgentMetadataIsNotAccepted(t *testing.T) {
	a := newTestApp(t)
	withoutEmbeddedAgent(t)
	addAgentBuild(t, a, "agent.exe", "not-go", "sha")
	readAgentEdition = func(string) (string, error) { return "", errors.New("not Go") }
	if _, ok := a.latestAgentBuild(); ok {
		t.Fatal("unverified executable offered as agent")
	}
}

func TestWrongAgentEditionCannotBeQueuedAsSelfUpdate(t *testing.T) {
	a := newTestApp(t)
	admin := sessionFor(t, a, "edition-admin", "admin")
	addAgentBuild(t, a, "agent.exe", "wrong-edition", "sha")
	readAgentEdition = func(string) (string, error) { return wrongAgentEdition(), nil }
	if _, err := a.DB.Exec(`INSERT INTO devices(hostname,agent_token)VALUES('pc','token')`); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := a.DB.QueryRow(`SELECT id FROM packages LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"package_id": {id}}
	r := httptest.NewRequest("POST", "/packages/agent-update", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(admin)
	w := httptest.NewRecorder()
	a.DeployAgentUpdate(w, r)
	var count int
	a.DB.QueryRow(`SELECT COUNT(*) FROM agent_tasks`).Scan(&count)
	if count != 0 || !strings.Contains(w.Header().Get("Location"), "error=") {
		t.Fatal("mismatched selfupdate queued")
	}
}
