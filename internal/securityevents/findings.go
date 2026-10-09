//go:build securityevents

package securityevents

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrFindingConflict = errors.New("карточка изменилась; обновите страницу")

const MaxFindingEvidence = 50
const maxFindings = 1000

type Rule struct {
	ID, Title, Explanation   string
	Enabled                  bool
	Threshold, WindowMinutes int
	Revision                 int64
}

var builtinRules = []Rule{
	{ID: "failed_logons", Title: "Серия неудачных входов", Explanation: "Неудачные входы на одном ПК с одинаковыми учётной записью и IP за выбранный интервал.", Enabled: true, Threshold: 5, WindowMinutes: 5, Revision: 1},
	{ID: "log_cleared", Title: "Очищен журнал Windows", Explanation: "Событие очистки журнала. Повторы для одного канала объединяются за выбранный интервал.", Enabled: true, Threshold: 1, WindowMinutes: 10, Revision: 1},
	{ID: "service_installed", Title: "Установлена служба", Explanation: "Установка службы. Повторы с одинаковым именем службы объединяются за выбранный интервал.", Enabled: true, Threshold: 1, WindowMinutes: 30, Revision: 1},
}

func ruleDefinition(id string) (Rule, bool) {
	for _, r := range builtinRules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

type Finding struct {
	ID, DeviceID, Revision, AssigneeID       int64
	RuleID, Title, Summary, Severity, Status string
	Threshold, WindowMinutes, EventCount     int
	FirstEvent, LastEvent, ObservedAt        time.Time
	groupKey                                 string
	ruleRevision, lastSeq                    int64
}
type FindingComment struct {
	Author, Text string
	CreatedAt    time.Time
}
type FindingDetails struct {
	Finding
	Evidence []Event
	Comments []FindingComment
}
type FindingFilter struct {
	DeviceID       int64
	RuleID, Status string
	Limit          int
}
type Exception struct {
	ID, DeviceID                 int64
	RuleID, Scope, Value, Reason string
	ExpiresAt                    time.Time
}

func (s *Store) initFindings() error {
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS events_rules(id TEXT PRIMARY KEY,enabled INTEGER NOT NULL,threshold INTEGER NOT NULL,window_minutes INTEGER NOT NULL,revision INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS events_rule_samples(event_seq INTEGER PRIMARY KEY,device_id INTEGER NOT NULL,rule_id TEXT NOT NULL,rule_revision INTEGER NOT NULL,group_key TEXT NOT NULL,event_time INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS events_samples_group ON events_rule_samples(device_id,rule_id,rule_revision,group_key,event_time,event_seq)`,
		`CREATE TRIGGER IF NOT EXISTS events_sample_cleanup AFTER DELETE ON events_records BEGIN DELETE FROM events_rule_samples WHERE event_seq=old.seq; END`,
		`CREATE TABLE IF NOT EXISTS events_findings(id INTEGER PRIMARY KEY AUTOINCREMENT,device_id INTEGER NOT NULL,rule_id TEXT NOT NULL,rule_revision INTEGER NOT NULL,group_key TEXT NOT NULL,title TEXT NOT NULL,summary TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'new',assignee_id INTEGER NOT NULL DEFAULT 0,revision INTEGER NOT NULL DEFAULT 1,threshold INTEGER NOT NULL,window_minutes INTEGER NOT NULL,event_count INTEGER NOT NULL,last_seq INTEGER NOT NULL,first_event INTEGER NOT NULL,last_event INTEGER NOT NULL,observed_at INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS events_findings_group ON events_findings(device_id,rule_id,rule_revision,group_key,status,last_event)`,
		`CREATE INDEX IF NOT EXISTS events_findings_observed ON events_findings(observed_at,id)`,
		`CREATE TABLE IF NOT EXISTS events_finding_evidence(finding_id INTEGER NOT NULL,device_id INTEGER NOT NULL,event_seq INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(finding_id,event_seq))`,
		`CREATE TABLE IF NOT EXISTS events_finding_comments(id INTEGER PRIMARY KEY AUTOINCREMENT,finding_id INTEGER NOT NULL,device_id INTEGER NOT NULL,author TEXT NOT NULL,body TEXT NOT NULL,created_at INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS events_comments_finding ON events_finding_comments(finding_id,id)`,
		`CREATE TABLE IF NOT EXISTS events_rule_exceptions(id INTEGER PRIMARY KEY AUTOINCREMENT,device_id INTEGER NOT NULL,rule_id TEXT NOT NULL,scope TEXT NOT NULL,value TEXT NOT NULL,reason TEXT NOT NULL,expires_at INTEGER NOT NULL)`,
	} {
		if _, err := s.db.Exec(statement); err != nil {
			return err
		}
	}
	for _, r := range builtinRules {
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO events_rules(id,enabled,threshold,window_minutes,revision)VALUES(?,?,?,?,?)`, r.ID, r.Enabled, r.Threshold, r.WindowMinutes, r.Revision); err != nil {
			return err
		}
	}
	return nil
}

func readRules(ctx context.Context, tx *sql.Tx) ([]Rule, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,enabled,threshold,window_minutes,revision FROM events_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Rule
	for rows.Next() {
		var r Rule
		if err = rows.Scan(&r.ID, &r.Enabled, &r.Threshold, &r.WindowMinutes, &r.Revision); err != nil {
			return nil, err
		}
		d, ok := ruleDefinition(r.ID)
		if !ok {
			return nil, ErrInvalid
		}
		r.Title, r.Explanation = d.Title, d.Explanation
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *Store) Rules(ctx context.Context) ([]Rule, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return readRules(ctx, tx)
}

// Changing a rule starts a fresh sample window; saved findings keep their rule
// snapshot. Existing raw history is never reinterpreted on enable or upgrade.
func (s *Store) SetRule(ctx context.Context, r Rule) error {
	_, ok := ruleDefinition(r.ID)
	if !ok || r.WindowMinutes < 1 || r.WindowMinutes > 120 || r.Threshold < 1 || r.Threshold > 100 || r.ID != "failed_logons" && r.Threshold != 1 {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old Rule
	if err = tx.QueryRowContext(ctx, `SELECT enabled,threshold,window_minutes,revision FROM events_rules WHERE id=?`, r.ID).Scan(&old.Enabled, &old.Threshold, &old.WindowMinutes, &old.Revision); err != nil {
		return err
	}
	if old.Revision != r.Revision {
		return ErrFindingConflict
	}
	if old.Enabled == r.Enabled && old.Threshold == r.Threshold && old.WindowMinutes == r.WindowMinutes {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE events_rules SET enabled=?,threshold=?,window_minutes=?,revision=revision+1 WHERE id=?`, r.Enabled, r.Threshold, r.WindowMinutes, r.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM events_rule_samples WHERE rule_id=?`, r.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func readExceptions(ctx context.Context, tx *sql.Tx, now time.Time) ([]Exception, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,device_id,rule_id,scope,value,reason,expires_at FROM events_rule_exceptions WHERE expires_at>? ORDER BY id DESC LIMIT 200`, now.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Exception
	for rows.Next() {
		var e Exception
		var stamp int64
		if err = rows.Scan(&e.ID, &e.DeviceID, &e.RuleID, &e.Scope, &e.Value, &e.Reason, &stamp); err != nil {
			return nil, err
		}
		e.ExpiresAt = time.UnixMilli(stamp).UTC()
		result = append(result, e)
	}
	return result, rows.Err()
}
func (s *Store) Exceptions(ctx context.Context) ([]Exception, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return readExceptions(ctx, tx, s.now())
}
func (s *Store) AddException(ctx context.Context, e Exception) error {
	validScope := e.RuleID == "failed_logons" && (e.Scope == "account" || e.Scope == "ip") || e.RuleID == "service_installed" && e.Scope == "service" || e.RuleID == "log_cleared" && e.Scope == "channel"
	e.Value = strings.TrimSpace(e.Value)
	e.Reason = strings.TrimSpace(e.Reason)
	if !validScope || e.DeviceID < 0 || e.Value == "" || !boundedText(e.Value, 2048, false) || utf8.RuneCountInString(e.Value) > 512 || e.Reason == "" || !boundedText(e.Reason, 2000, true) || utf8.RuneCountInString(e.Reason) > 500 || !e.ExpiresAt.After(s.now()) || e.ExpiresAt.After(s.now().Add(7*24*time.Hour)) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM events_rule_exceptions WHERE expires_at<=?`, s.now().UnixMilli()); err != nil {
		return err
	}
	var n int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM events_rule_exceptions`).Scan(&n); err != nil {
		return err
	}
	if n >= 200 {
		return fmt.Errorf("%w: предел 200 исключений", ErrInvalid)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO events_rule_exceptions(device_id,rule_id,scope,value,reason,expires_at)VALUES(?,?,?,?,?,?)`, e.DeviceID, e.RuleID, e.Scope, e.Value, e.Reason, e.ExpiresAt.UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) DeleteException(ctx context.Context, id int64) error {
	if id <= 0 {
		return ErrInvalid
	}
	r, err := s.db.ExecContext(ctx, `DELETE FROM events_rule_exceptions WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

type observedEvent struct {
	seq   int64
	event Event
}
type ruleGroup struct {
	rule                   Rule
	key, summary, severity string
	anchor                 int64
}

func ruleEvent(e Event) (id, key, summary, severity string) {
	account := AccountName(e)
	switch {
	case e.Channel == "Security" && e.EventID == 4625:
		id = "failed_logons"
		key = account + "\x00" + e.Fields["IpAddress"]
		summary = "Учётная запись: " + displayValue(account) + "; IP: " + displayValue(e.Fields["IpAddress"])
		severity = "medium"
	case e.EventID == 1102 && e.Channel == "Security" || e.EventID == 104 && e.Channel == "System":
		id = "log_cleared"
		key = ClearedChannel(e)
		summary = "Очищен канал: " + key
		severity = "high"
	case e.EventID == 7045 && e.Channel == "System":
		id = "service_installed"
		key = e.Fields["ServiceName"]
		summary = "Служба: " + displayValue(key)
		severity = "info"
	}
	key = tokenHash(strings.ToLower(key))
	return
}

func matchesException(ex Exception, device int64, e Event, rule string) bool {
	if ex.RuleID != rule || ex.DeviceID != 0 && ex.DeviceID != device {
		return false
	}
	value := ""
	switch ex.Scope {
	case "account":
		value = AccountName(e)
	case "ip":
		value = e.Fields["IpAddress"]
	case "service":
		value = e.Fields["ServiceName"]
	case "channel":
		value = ClearedChannel(e)
	}
	return value != "" && strings.EqualFold(strings.TrimSpace(value), ex.Value)
}

// Events, rule samples, findings and evidence commit together. A lost ACK or a
// duplicate event therefore cannot increment a finding or rerun correlation.
func detectFindings(ctx context.Context, tx *sql.Tx, device int64, fresh []observedEvent, now time.Time) error {
	if len(fresh) == 0 {
		return nil
	}
	rules, err := readRules(ctx, tx)
	if err != nil {
		return err
	}
	exceptions, err := readExceptions(ctx, tx, now)
	if err != nil {
		return err
	}
	byID := map[string]Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	groups := map[string]ruleGroup{}
	for _, item := range fresh {
		id, key, summary, severity := ruleEvent(item.event)
		r, ok := byID[id]
		if !ok || !r.Enabled {
			continue
		}
		excluded := false
		for _, ex := range exceptions {
			if matchesException(ex, device, item.event, id) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO events_rule_samples(event_seq,device_id,rule_id,rule_revision,group_key,event_time)VALUES(?,?,?,?,?,?)`, item.seq, device, id, r.Revision, key, item.event.TimeUTC.UnixMilli()); err != nil {
			return err
		}
		groupID := id + key
		g := groups[groupID]
		g.rule, g.key, g.summary, g.severity = r, key, summary, severity
		g.anchor = max(g.anchor, item.event.TimeUTC.UnixMilli())
		groups[groupID] = g
	}
	for _, g := range groups {
		if err = correlateGroup(ctx, tx, device, g, now); err != nil {
			return err
		}
	}
	return nil
}

const findingColumns = `id,device_id,rule_id,rule_revision,group_key,title,summary,severity,status,assignee_id,revision,threshold,window_minutes,event_count,last_seq,first_event,last_event,observed_at`

func scanFinding(row interface{ Scan(...any) error }) (Finding, error) {
	var f Finding
	var first, last, observed int64
	err := row.Scan(&f.ID, &f.DeviceID, &f.RuleID, &f.ruleRevision, &f.groupKey, &f.Title, &f.Summary, &f.Severity, &f.Status, &f.AssigneeID, &f.Revision, &f.Threshold, &f.WindowMinutes, &f.EventCount, &f.lastSeq, &first, &last, &observed)
	f.FirstEvent, f.LastEvent, f.ObservedAt = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC(), time.UnixMilli(observed).UTC()
	return f, err
}

func correlateGroup(ctx context.Context, tx *sql.Tx, device int64, g ruleGroup, now time.Time) error {
	// Include out-of-order deliveries in the same durable event-time window.
	if err := tx.QueryRowContext(ctx, `SELECT MAX(event_time) FROM events_rule_samples WHERE device_id=? AND rule_id=? AND rule_revision=? AND group_key=?`, device, g.rule.ID, g.rule.Revision, g.key).Scan(&g.anchor); err != nil {
		return err
	}
	from := g.anchor - int64(g.rule.WindowMinutes)*int64(time.Minute/time.Millisecond)
	var cutoff int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(last_seq),0) FROM events_findings WHERE device_id=? AND rule_id=? AND rule_revision=? AND group_key=? AND status IN('closed','false_positive')`, device, g.rule.ID, g.rule.Revision, g.key).Scan(&cutoff); err != nil {
		return err
	}
	args := []any{device, g.rule.ID, g.rule.Revision, g.key, from, g.anchor, cutoff}
	where := ` FROM events_rule_samples WHERE device_id=? AND rule_id=? AND rule_revision=? AND group_key=? AND event_time>=? AND event_time<=? AND event_seq>?`
	var count int
	var first, last, maxSeq int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MIN(event_time),0),COALESCE(MAX(event_time),0),COALESCE(MAX(event_seq),0)`+where, args...).Scan(&count, &first, &last, &maxSeq); err != nil {
		return err
	}
	if count < g.rule.Threshold {
		return nil
	}
	f, err := scanFinding(tx.QueryRowContext(ctx, `SELECT `+findingColumns+` FROM events_findings WHERE device_id=? AND rule_id=? AND rule_revision=? AND group_key=? AND status IN('new','in_progress') AND last_event>=? ORDER BY id DESC LIMIT 1`, device, g.rule.ID, g.rule.Revision, g.key, from))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	previousSeq := int64(0)
	if errors.Is(err, sql.ErrNoRows) {
		result, insertErr := tx.ExecContext(ctx, `INSERT INTO events_findings(device_id,rule_id,rule_revision,group_key,title,summary,severity,threshold,window_minutes,event_count,last_seq,first_event,last_event,observed_at)VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, device, g.rule.ID, g.rule.Revision, g.key, g.rule.Title, g.summary, g.severity, g.rule.Threshold, g.rule.WindowMinutes, count, maxSeq, first, last, now.UnixMilli())
		if insertErr != nil {
			return insertErr
		}
		f.ID, err = result.LastInsertId()
		if err != nil {
			return err
		}
	} else {
		previousSeq = f.lastSeq
		newArgs := append([]any{}, args...)
		newArgs[6] = max(cutoff, previousSeq)
		var added int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*)`+where, newArgs...).Scan(&added); err != nil {
			return err
		}
		if added == 0 {
			return nil
		}
		if _, err = tx.ExecContext(ctx, `UPDATE events_findings SET event_count=event_count+?,last_seq=?,first_event=?,last_event=?,observed_at=?,revision=revision+1 WHERE id=?`, added, maxSeq, min(first, f.FirstEvent.UnixMilli()), max(last, f.LastEvent.UnixMilli()), now.UnixMilli(), f.ID); err != nil {
			return err
		}
	}
	var saved int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM events_finding_evidence WHERE finding_id=?`, f.ID).Scan(&saved); err != nil {
		return err
	}
	if saved >= MaxFindingEvidence {
		return nil
	}
	query := `SELECT r.seq,r.payload FROM events_records r JOIN events_rule_samples s ON s.event_seq=r.seq WHERE s.device_id=? AND s.rule_id=? AND s.rule_revision=? AND s.group_key=? AND s.event_time>=? AND s.event_time<=? AND s.event_seq>? ORDER BY r.seq LIMIT ?`
	evidenceArgs := append([]any{}, args...)
	evidenceArgs[6] = max(previousSeq, cutoff)
	evidenceArgs = append(evidenceArgs, MaxFindingEvidence-saved)
	rows, err := tx.QueryContext(ctx, query, evidenceArgs...)
	if err != nil {
		return err
	}
	type evidence struct {
		seq     int64
		payload []byte
	}
	var pending []evidence
	for rows.Next() {
		var e evidence
		if err = rows.Scan(&e.seq, &e.payload); err != nil {
			break
		}
		pending = append(pending, e)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, e := range pending {
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO events_finding_evidence(finding_id,device_id,event_seq,payload)VALUES(?,?,?,?)`, f.ID, device, e.seq, e.payload); err != nil {
			return err
		}
	}
	return nil
}

func validFindingState(state string) bool {
	return state == "new" || state == "in_progress" || state == "closed" || state == "false_positive"
}
func (s *Store) Findings(ctx context.Context, filter FindingFilter) ([]Finding, error) {
	if filter.DeviceID < 0 || filter.Status != "" && filter.Status != "all" && filter.Status != "active" && !validFindingState(filter.Status) {
		return nil, ErrInvalid
	}
	if filter.RuleID != "" {
		if _, ok := ruleDefinition(filter.RuleID); !ok {
			return nil, ErrInvalid
		}
	}
	query := `SELECT ` + findingColumns + ` FROM events_findings WHERE observed_at>=?`
	args := []any{s.now().Add(-RetentionDays * 24 * time.Hour).UnixMilli()}
	if filter.DeviceID > 0 {
		query += ` AND device_id=?`
		args = append(args, filter.DeviceID)
	}
	if filter.RuleID != "" {
		query += ` AND rule_id=?`
		args = append(args, filter.RuleID)
	}
	if filter.Status == "" || filter.Status == "active" {
		query += ` AND status IN('new','in_progress')`
	} else if filter.Status != "all" {
		query += ` AND status=?`
		args = append(args, filter.Status)
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, 100)
	query += ` ORDER BY observed_at DESC,id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Finding
	for rows.Next() {
		f, scanErr := scanFinding(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, f)
	}
	return result, rows.Err()
}

func (s *Store) Finding(ctx context.Context, id int64) (FindingDetails, error) {
	if id <= 0 {
		return FindingDetails{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return FindingDetails{}, err
	}
	defer tx.Rollback()
	f, err := scanFinding(tx.QueryRowContext(ctx, `SELECT `+findingColumns+` FROM events_findings WHERE id=? AND observed_at>=?`, id, s.now().Add(-RetentionDays*24*time.Hour).UnixMilli()))
	result := FindingDetails{Finding: f}
	if err != nil {
		return result, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT payload FROM events_finding_evidence WHERE finding_id=? ORDER BY event_seq LIMIT ?`, id, MaxFindingEvidence)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var b []byte
		var e Event
		if err = rows.Scan(&b); err != nil {
			break
		}
		if len(b) > 4096 || json.Unmarshal(b, &e) != nil {
			err = ErrInvalid
			break
		}
		result.Evidence = append(result.Evidence, e)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return result, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT author,body,created_at FROM events_finding_comments WHERE finding_id=? ORDER BY id LIMIT 20`, id)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var c FindingComment
		var stamp int64
		if err = rows.Scan(&c.Author, &c.Text, &stamp); err != nil {
			break
		}
		c.CreatedAt = time.UnixMilli(stamp).UTC()
		result.Comments = append(result.Comments, c)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	return result, err
}

func (s *Store) UpdateFinding(ctx context.Context, id, revision int64, state string, assignee int64, comment, author string) error {
	comment = strings.TrimSpace(comment)
	if id <= 0 || revision <= 0 || assignee < 0 || !validFindingState(state) || !boundedText(comment, 8000, true) || utf8.RuneCountInString(comment) > 2000 || author == "" || !boundedText(author, 256, false) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	f, err := scanFinding(tx.QueryRowContext(ctx, `SELECT `+findingColumns+` FROM events_findings WHERE id=? AND observed_at>=?`, id, s.now().Add(-RetentionDays*24*time.Hour).UnixMilli()))
	if err != nil {
		return err
	}
	if f.Revision != revision {
		return ErrFindingConflict
	}
	if comment != "" {
		var n int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM events_finding_comments WHERE finding_id=?`, id).Scan(&n); err != nil {
			return err
		}
		if n >= 20 {
			return fmt.Errorf("%w: предел 20 комментариев", ErrInvalid)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO events_finding_comments(finding_id,device_id,author,body,created_at)VALUES(?,?,?,?,?)`, id, f.DeviceID, author, comment, s.now().UnixMilli()); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE events_findings SET status=?,assignee_id=?,revision=revision+1 WHERE id=?`, state, assignee, id); err != nil {
		return err
	}
	return tx.Commit()
}

func cleanupFindings(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM events_findings WHERE observed_at<?`, now.Add(-RetentionDays*24*time.Hour).UnixMilli()); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM events_findings`).Scan(&n); err != nil {
		return err
	}
	if n > maxFindings {
		if _, err := tx.ExecContext(ctx, `DELETE FROM events_findings WHERE id IN(SELECT id FROM events_findings ORDER BY observed_at,id LIMIT ?)`, n-maxFindings); err != nil {
			return err
		}
	}
	for _, table := range []string{"events_finding_evidence", "events_finding_comments"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE finding_id NOT IN(SELECT id FROM events_findings)`); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM events_rule_exceptions WHERE expires_at<=?`, now.UnixMilli())
	return err
}
