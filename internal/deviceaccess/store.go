// Package deviceaccess manages static device groups and per-user device grants.
package deviceaccess

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalid  = errors.New("invalid device access settings")
	ErrConflict = errors.New("device access settings changed")
)

type Group struct {
	ID, Revision      int64
	Name, Description string
	Members           int
}
type Scope struct {
	Mode     string
	Revision int64
	GroupIDs []int64
}

func Groups(ctx context.Context, db *sql.DB) ([]Group, error) {
	rows, err := db.QueryContext(ctx, `SELECT g.id,g.name,g.description,g.revision,COUNT(m.device_id) FROM device_groups g LEFT JOIN device_group_members m ON m.group_id=g.id GROUP BY g.id ORDER BY g.name,g.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []Group
	for rows.Next() {
		var g Group
		if err = rows.Scan(&g.ID, &g.Name, &g.Description, &g.Revision, &g.Members); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func UserScope(ctx context.Context, db *sql.DB, id int64) (Scope, error) {
	s := Scope{Mode: "all"}
	err := db.QueryRowContext(ctx, "SELECT mode,revision FROM user_device_access WHERE user_id=?", id).Scan(&s.Mode, &s.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	rows, err := db.QueryContext(ctx, "SELECT group_id FROM user_device_groups WHERE user_id=? ORDER BY group_id", id)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var group int64
		if err = rows.Scan(&group); err != nil {
			return s, err
		}
		s.GroupIDs = append(s.GroupIDs, group)
	}
	return s, rows.Err()
}

func GroupByID(ctx context.Context, db *sql.DB, id int64) (Group, []int64, error) {
	var g Group
	err := db.QueryRowContext(ctx, "SELECT id,name,description,revision FROM device_groups WHERE id=?", id).Scan(&g.ID, &g.Name, &g.Description, &g.Revision)
	if err != nil {
		return g, nil, err
	}
	rows, err := db.QueryContext(ctx, "SELECT device_id FROM device_group_members WHERE group_id=? ORDER BY device_id", id)
	if err != nil {
		return g, nil, err
	}
	defer rows.Close()
	var members []int64
	for rows.Next() {
		var member int64
		if err = rows.Scan(&member); err != nil {
			return g, nil, err
		}
		members = append(members, member)
	}
	g.Members = len(members)
	return g, members, rows.Err()
}

func normalize(name, description string) (string, string, error) {
	name, description = strings.TrimSpace(name), strings.TrimSpace(description)
	if name == "" || utf8.RuneCountInString(name) > 80 || utf8.RuneCountInString(description) > 500 {
		return "", "", ErrInvalid
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", "", ErrInvalid
		}
	}
	return name, description, nil
}

func IDs(values []string, max int) ([]int64, error) {
	if len(values) > max {
		return nil, ErrInvalid
	}
	seen := map[int64]bool{}
	var ids []int64
	for _, v := range values {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			return nil, ErrInvalid
		}
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	return ids, nil
}

func existingIDs(ctx context.Context, tx *sql.Tx, table string, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE id IN ("+placeholders+")", args...).Scan(&count); err != nil {
		return err
	}
	if count != len(ids) {
		return ErrInvalid
	}
	return nil
}

func audit(ctx context.Context, tx *sql.Tx, actor int64, action, target, detail string) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO audit_log(user_id,action,target,detail) VALUES(?,?,?,?)", actor, action, target, detail)
	return err
}

func CreateGroup(ctx context.Context, db *sql.DB, name, description string, actor int64) (int64, error) {
	name, description, err := normalize(name, description)
	if err != nil {
		return 0, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM device_groups").Scan(&count); err != nil {
		return 0, err
	}
	if count >= 500 {
		return 0, ErrInvalid
	}
	result, err := tx.ExecContext(ctx, "INSERT INTO device_groups(name,name_key,description) VALUES(?,?,?)", name, strings.ToLower(name), description)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err = audit(ctx, tx, actor, "device_group_create", name, ""); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func UpdateGroup(ctx context.Context, db *sql.DB, g Group, members []int64, actor int64) error {
	name, description, err := normalize(g.Name, g.Description)
	if err != nil || g.ID <= 0 || g.Revision <= 0 || len(members) > 5000 {
		return ErrInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = existingIDs(ctx, tx, "devices", members); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, "UPDATE device_groups SET name=?,name_key=?,description=?,revision=revision+1 WHERE id=? AND revision=?", name, strings.ToLower(name), description, g.ID, g.Revision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM device_group_members WHERE group_id=?", g.ID); err != nil {
		return err
	}
	for _, id := range members {
		if _, err = tx.ExecContext(ctx, "INSERT INTO device_group_members(group_id,device_id) VALUES(?,?)", g.ID, id); err != nil {
			return err
		}
	}
	if err = revokeTasks(ctx, tx); err != nil {
		return err
	}
	if err = audit(ctx, tx, actor, "device_group_update", name, fmt.Sprintf("members=%d", len(members))); err != nil {
		return err
	}
	return tx.Commit()
}

func DeleteGroup(ctx context.Context, db *sql.DB, id, revision, actor int64) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "DELETE FROM device_groups WHERE id=? AND revision=?", id, revision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	// The user's groups mode is retained even when every grant is removed.
	if err = revokeTasks(ctx, tx); err != nil {
		return err
	}
	if err = audit(ctx, tx, actor, "device_group_delete", strconv.FormatInt(id, 10), ""); err != nil {
		return err
	}
	return tx.Commit()
}

// InitialScope is called inside user creation: invalid grants never leave behind
// an unexpectedly unrestricted account after a partially successful creation.
func InitialScope(ctx context.Context, tx *sql.Tx, user int64, mode string, groups []int64) error {
	if mode != "all" && mode != "groups" {
		return ErrInvalid
	}
	if len(groups) > 500 {
		return ErrInvalid
	}
	if mode == "all" {
		groups = nil
	}
	if err := existingIDs(ctx, tx, "device_groups", groups); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO user_device_access(user_id,mode,revision) VALUES(?,?,1)", user, mode); err != nil {
		return err
	}
	for _, group := range groups {
		if _, err := tx.ExecContext(ctx, "INSERT INTO user_device_groups(user_id,group_id) VALUES(?,?)", user, group); err != nil {
			return err
		}
	}
	return nil
}

func SetUserScope(ctx context.Context, db *sql.DB, user int64, s Scope, actor int64) error {
	if (s.Mode != "all" && s.Mode != "groups") || s.Revision < 0 || len(s.GroupIDs) > 500 {
		return ErrInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var role string
	if err = tx.QueryRowContext(ctx, "SELECT role FROM users WHERE id=?", user).Scan(&role); err != nil {
		return err
	}
	if role == "admin" {
		return ErrInvalid
	}
	var revision int64
	err = tx.QueryRowContext(ctx, "SELECT revision FROM user_device_access WHERE user_id=?", user).Scan(&revision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if revision != s.Revision {
		return ErrConflict
	}
	groups := s.GroupIDs
	if s.Mode == "all" {
		groups = nil
	}
	if err = existingIDs(ctx, tx, "device_groups", groups); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM user_device_groups WHERE user_id=?", user); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO user_device_access(user_id,mode,revision) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET mode=excluded.mode,revision=excluded.revision`, user, s.Mode, revision+1); err != nil {
		return err
	}
	for _, group := range groups {
		if _, err = tx.ExecContext(ctx, "INSERT INTO user_device_groups(user_id,group_id) VALUES(?,?)", user, group); err != nil {
			return err
		}
	}
	if err = revokeTasks(ctx, tx); err != nil {
		return err
	}
	if err = audit(ctx, tx, actor, "user_device_scope", strconv.FormatInt(user, 10), fmt.Sprintf("mode=%s groups=%d", s.Mode, len(groups))); err != nil {
		return err
	}
	return tx.Commit()
}

func revokeTasks(ctx context.Context, tx *sql.Tx) error {
	predicate := `EXISTS(SELECT 1 FROM user_device_access ua JOIN users u ON u.id=ua.user_id WHERE ua.user_id=agent_tasks.created_by AND ua.mode='groups' AND u.role<>'admin')
        AND NOT EXISTS(SELECT 1 FROM device_group_members gm JOIN user_device_groups ug ON ug.group_id=gm.group_id WHERE ug.user_id=agent_tasks.created_by AND gm.device_id=agent_tasks.device_id)`
	if _, err := tx.ExecContext(ctx, `UPDATE agent_tasks SET status='cancelled',result='Доступ к устройству отозван',done_at=datetime('now') WHERE status='pending' AND `+predicate); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE agent_tasks SET cancel_requested=1 WHERE status IN ('sent','running') AND task_protocol=2 AND `+predicate)
	return err
}
