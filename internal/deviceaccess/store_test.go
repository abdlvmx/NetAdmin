package deviceaccess

import (
	"context"
	"database/sql"
	"errors"
	"netadmin/internal/db"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) (*sql.DB, context.Context, int64, int64, int64) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "access.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err = db.InitSchema(d); err != nil {
		t.Fatal(err)
	}
	result, err := d.Exec("INSERT INTO users(username,role,password_hash) VALUES('operator','user','test')")
	if err != nil {
		t.Fatal(err)
	}
	user, _ := result.LastInsertId()
	result, err = d.Exec("INSERT INTO devices(hostname) VALUES('A')")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := result.LastInsertId()
	result, err = d.Exec("INSERT INTO devices(hostname) VALUES('B')")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := result.LastInsertId()
	return d, context.Background(), user, a, b
}

func TestGroupRevisionValidationAndScopeDeletionDoesNotGrantAll(t *testing.T) {
	d, ctx, user, a, b := fixture(t)
	original, err := UserScope(ctx, d, user)
	if err != nil || original.Mode != "all" || original.Revision != 0 {
		t.Fatal("legacy access changed")
	}
	group, err := CreateGroup(ctx, d, "Бухгалтерия", "ПК отдела", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CreateGroup(ctx, d, "БУХГАЛТЕРИЯ", "", 0); err == nil {
		t.Fatal("duplicate case-insensitive group accepted")
	}
	if err = UpdateGroup(ctx, d, Group{ID: group, Revision: 1, Name: "Бухгалтерия"}, []int64{a}, 0); err != nil {
		t.Fatal(err)
	}
	if err = UpdateGroup(ctx, d, Group{ID: group, Revision: 1, Name: "Изменено"}, []int64{b}, 0); !errors.Is(err, ErrConflict) {
		t.Fatal("stale membership update accepted")
	}
	if err = UpdateGroup(ctx, d, Group{ID: group, Revision: 2, Name: "Бухгалтерия"}, []int64{99999}, 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown device accepted")
	}
	_, members, err := GroupByID(ctx, d, group)
	if err != nil || len(members) != 1 || members[0] != a {
		t.Fatal("failed update altered group")
	}
	if err = SetUserScope(ctx, d, user, Scope{Mode: "groups", GroupIDs: []int64{group}}, 0); err != nil {
		t.Fatal(err)
	}
	if err = SetUserScope(ctx, d, user, Scope{Mode: "all", Revision: 0}, 0); !errors.Is(err, ErrConflict) {
		t.Fatal("stale grant update accepted")
	}
	if err = SetUserScope(ctx, d, user, Scope{Mode: "groups", Revision: 1, GroupIDs: []int64{99999}}, 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown group accepted")
	}
	if err = DeleteGroup(ctx, d, group, 2, 0); err != nil {
		t.Fatal(err)
	}
	scope, err := UserScope(ctx, d, user)
	if err != nil || scope.Mode != "groups" || len(scope.GroupIDs) != 0 {
		t.Fatalf("deleted final group broadened access: %+v %v", scope, err)
	}
	if err = SetUserScope(ctx, d, user, Scope{Mode: "all", Revision: scope.Revision}, 0); err != nil {
		t.Fatal(err)
	}
}

func TestRevocationCancelsPendingAndRequestsProtocolTwoCancellation(t *testing.T) {
	d, ctx, user, a, b := fixture(t)
	group, err := CreateGroup(ctx, d, "Отдел", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = UpdateGroup(ctx, d, Group{ID: group, Name: "Отдел", Revision: 1}, []int64{a}, 0); err != nil {
		t.Fatal(err)
	}
	if err = SetUserScope(ctx, d, user, Scope{Mode: "groups", GroupIDs: []int64{group}}, 0); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		device   int64
		state    string
		protocol int
	}{{a, "pending", 2}, {b, "pending", 2}, {b, "running", 2}, {b, "sent", 1}} {
		if _, err = d.Exec("INSERT INTO agent_tasks(device_id,kind,payload,label,status,created_by,task_protocol) VALUES(?,'command','ipconfig','test',?,?,?)", row.device, row.state, user, row.protocol); err != nil {
			t.Fatal(err)
		}
	}
	if err = SetUserScope(ctx, d, user, Scope{Mode: "groups", Revision: 1, GroupIDs: []int64{group}}, 0); err != nil {
		t.Fatal(err)
	}
	rows, err := d.Query("SELECT status,cancel_requested FROM agent_tasks ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	expected := []struct {
		state  string
		cancel int
	}{{"pending", 0}, {"cancelled", 0}, {"running", 1}, {"sent", 0}}
	i := 0
	for rows.Next() {
		var state string
		var cancel int
		if err = rows.Scan(&state, &cancel); err != nil {
			t.Fatal(err)
		}
		if state != expected[i].state || cancel != expected[i].cancel {
			t.Fatalf("task %d: %s %d", i, state, cancel)
		}
		i++
	}
	if i != len(expected) {
		t.Fatal("lost task rows")
	}
}

func TestInitialGrantsRollbackAndAdminCannotBeRestricted(t *testing.T) {
	d, ctx, user, _, _ := fixture(t)
	if _, err := d.Exec("UPDATE users SET role='admin' WHERE id=?", user); err != nil {
		t.Fatal(err)
	}
	if err := SetUserScope(ctx, d, user, Scope{Mode: "groups"}, 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("restricted an administrator")
	}
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = InitialScope(ctx, tx, user, "groups", []int64{99999}); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid initial grants accepted")
	}
	tx.Rollback()
	scope, err := UserScope(ctx, d, user)
	if err != nil || scope.Mode != "all" {
		t.Fatal("invalid initial scope changed access")
	}
	ids, err := IDs([]string{"1", "1", "2"}, 5)
	if err != nil || len(ids) != 2 {
		t.Fatal("ID dedup failed")
	}
	for _, bad := range []string{"0", "-1", "bad", "1;DELETE FROM users"} {
		if _, err = IDs([]string{bad}, 5); !errors.Is(err, ErrInvalid) {
			t.Fatal("malformed ID accepted")
		}
	}
}
