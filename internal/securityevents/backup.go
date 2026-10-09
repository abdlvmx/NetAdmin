//go:build securityevents

package securityevents

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxBackupSize = 1 << 30

var backupName = regexp.MustCompile(`^events-[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[a-f0-9]{32}\.db$`)

type BackupInfo struct {
	Name    string
	Size    int64
	Created time.Time
}

// ListBackups reads only this module's files; arbitrary filenames and links
// are never eligible for restore or rotation. A missing directory is empty.
func ListBackups(dir string) ([]BackupInfo, error) {
	f, err := os.Open(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(2049)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 2048 {
		return nil, errors.New("слишком много файлов в каталоге копий Events")
	}
	var out []BackupInfo
	for _, e := range entries {
		if !backupName.MatchString(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			return nil, err
		}
		if !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, BackupInfo{Name: e.Name(), Size: fi.Size(), Created: fi.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

func BackupPath(dir, name string) (string, error) {
	if !backupName.MatchString(name) || filepath.Base(name) != name {
		return "", ErrInvalid
	}
	path := filepath.Join(dir, name)
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() || fi.Size() == 0 || fi.Size() > maxBackupSize {
		return "", ErrInvalid
	}
	return path, nil
}

func openBackup(path string, readOnly bool) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	q := url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(3000)"}}
	if readOnly {
		q.Set("mode", "ro")
	}
	u.RawQuery = q.Encode()
	d, err := sql.Open("sqlite", u.String())
	if err == nil {
		d.SetMaxOpenConns(1)
	}
	return d, err
}

// VerifyBackup checks integrity and the format/schema used by this edition.
// Main inventory databases, truncated files and future formats are rejected.
func VerifyBackup(ctx context.Context, path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() == 0 || fi.Size() > maxBackupSize {
		return ErrInvalid
	}
	d, err := openBackup(path, true)
	if err != nil {
		return err
	}
	defer d.Close()
	var id, version int
	if err = d.QueryRowContext(ctx, `PRAGMA application_id`).Scan(&id); err != nil {
		return err
	}
	if err = d.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if id != 1312900438 || version != 1 {
		return errors.New("это не поддерживаемая копия Events")
	}
	rows, err := d.QueryContext(ctx, `PRAGMA integrity_check`)
	if err != nil {
		return err
	}
	valid, n := true, 0
	for rows.Next() {
		var result string
		if err = rows.Scan(&result); err != nil {
			break
		}
		n++
		valid = valid && result == "ok"
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if !valid || n != 1 {
		return errors.New("копия Events повреждена")
	}
	for _, query := range []string{
		`SELECT device_id,enabled,profile,generation,consent_hash FROM events_policies LIMIT 0`,
		`SELECT device_id,current_hash FROM events_registrations LIMIT 0`,
		`SELECT device_id,payload,last_received FROM events_status LIMIT 0`,
		`SELECT device_id,generation,policy_at,last_poll,queue_since,loss_at FROM events_delivery LIMIT 0`,
		`SELECT seq,device_id,channel,stream_id,record_id,event_time,received_at,payload,payload_hash FROM events_records LIMIT 0`,
		`SELECT seq,device_id,batch_id,payload_hash,received_at FROM events_receipts LIMIT 0`,
		`SELECT seq,device_id,channel,reason,received_at FROM events_gaps LIMIT 0`,
		`SELECT id,enabled,threshold,window_minutes,revision FROM events_rules LIMIT 0`,
		`SELECT event_seq,device_id,rule_id,rule_revision,group_key,event_time FROM events_rule_samples LIMIT 0`,
		`SELECT id,device_id,rule_id,rule_revision,group_key,title,summary,severity,status,assignee_id,revision,threshold,window_minutes,event_count,last_seq,first_event,last_event,observed_at FROM events_findings LIMIT 0`,
		`SELECT finding_id,device_id,event_seq,payload FROM events_finding_evidence LIMIT 0`,
		`SELECT id,finding_id,device_id,author,body,created_at FROM events_finding_comments LIMIT 0`,
		`SELECT id,device_id,rule_id,scope,value,reason,expires_at FROM events_rule_exceptions LIMIT 0`,
	} {
		r, e := d.QueryContext(ctx, query)
		if e != nil {
			return fmt.Errorf("схема копии Events: %w", e)
		}
		r.Close()
	}
	return nil
}

func (s *Store) CreateBackup(ctx context.Context, dir string, keep int) (BackupInfo, error) {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	if keep < 0 {
		return BackupInfo{}, ErrInvalid
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return BackupInfo{}, err
	}
	if _, err := ListBackups(dir); err != nil {
		return BackupInfo{}, err
	}
	nonce, err := randomGeneration()
	if err != nil {
		return BackupInfo{}, err
	}
	name := "events-" + s.now().UTC().Format("20060102T150405.000000000Z") + "-" + nonce + ".db"
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	defer removeSnapshot(tmp)
	// SQLite supplies a transactionally consistent snapshot of WAL changes.
	if _, err = s.db.ExecContext(ctx, `VACUUM INTO ?`, tmp); err != nil {
		return BackupInfo{}, err
	}
	if err = os.Chmod(tmp, 0600); err != nil {
		return BackupInfo{}, err
	}
	if err = VerifyBackup(ctx, tmp); err != nil {
		return BackupInfo{}, err
	}
	if err = os.Rename(tmp, path); err != nil {
		return BackupInfo{}, err
	}
	list, err := ListBackups(dir)
	if err != nil {
		return BackupInfo{}, err
	}
	if keep > 0 && len(list) > keep {
		for _, old := range list[keep:] {
			if err = os.Remove(filepath.Join(dir, old.Name)); err != nil {
				return BackupInfo{}, fmt.Errorf("копия создана, ротация: %w", err)
			}
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return BackupInfo{}, err
	}
	return BackupInfo{Name: name, Size: fi.Size(), Created: fi.ModTime().UTC()}, nil
}

func PendingRestore(path string) bool {
	fi, err := os.Lstat(path + ".restore")
	return err == nil && fi.Mode().IsRegular()
}

func removeSnapshot(path string) {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}
}

// Preparation always works on a new copy, leaving the selected backup intact.
// Recovered consent and stale delivery health must never restart collection.
func prepareRestore(ctx context.Context, path string) error {
	if err := VerifyBackup(ctx, path); err != nil {
		return err
	}
	d, err := openBackup(path, false)
	if err != nil {
		return err
	}
	defer d.Close()
	if _, err = d.ExecContext(ctx, `PRAGMA journal_mode=DELETE`); err != nil {
		return err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT device_id FROM events_policies`)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		generation, e := randomGeneration()
		if e != nil {
			return e
		}
		if _, err = tx.ExecContext(ctx, `UPDATE events_policies SET enabled=0,generation=? WHERE device_id=?`, generation, id); err != nil {
			return err
		}
	}
	for _, table := range []string{"events_status", "events_delivery", "events_rule_samples"} {
		if _, err = tx.ExecContext(ctx, `DELETE FROM `+table); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) StageRestore(ctx context.Context, dir, name string) error {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	path, err := BackupPath(dir, name)
	if err != nil {
		return err
	}
	if err = VerifyBackup(ctx, path); err != nil {
		return err
	}
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.CreateTemp(filepath.Dir(s.path), "events-restore-*.tmp")
	if err != nil {
		return err
	}
	tmp := out.Name()
	defer removeSnapshot(tmp)
	if err = out.Chmod(0600); err == nil {
		var n int64
		n, err = io.Copy(out, io.LimitReader(in, maxBackupSize+1))
		if n > maxBackupSize {
			err = ErrInvalid
		}
	}
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = prepareRestore(ctx, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, s.path+".restore")
}

func (s *Store) CancelRestore() error {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	err := os.Remove(s.path + ".restore")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// ApplyRestore runs before Open, while neither SQLite nor an Events worker can
// use the files. Every renamed original sidecar is restored if replacement fails.
// A damaged pending file stops startup and leaves the current database intact.
func ApplyRestore(ctx context.Context, path string) (string, error) {
	pending := path + ".restore"
	if _, err := os.Lstat(pending); errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	if err := prepareRestore(ctx, pending); err != nil {
		return "", err
	}
	nonce, err := randomGeneration()
	if err != nil {
		return "", err
	}
	saved := path + ".before-restore-" + nonce
	var moved []string
	rollback := func(cause error) error {
		for i := len(moved) - 1; i >= 0; i-- {
			if err := os.Rename(saved+moved[i], path+moved[i]); err != nil {
				return fmt.Errorf("%v; откат не выполнен: %w; прежние файлы: %s", cause, err, saved)
			}
		}
		return cause
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		fi, e := os.Lstat(path + suffix)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return "", rollback(e)
		}
		if !fi.Mode().IsRegular() {
			return "", rollback(ErrInvalid)
		}
		if e = os.Rename(path+suffix, saved+suffix); e != nil {
			return "", rollback(e)
		}
		moved = append(moved, suffix)
	}
	if err = os.Rename(pending, path); err != nil {
		return "", rollback(err)
	}
	if len(moved) == 0 {
		return "", nil
	}
	return saved, nil
}
