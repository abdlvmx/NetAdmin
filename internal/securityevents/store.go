//go:build securityevents

package securityevents

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrInvalid       = errors.New("некорректные данные Events")
	ErrDisabled      = errors.New("сбор Events выключен")
	ErrGeneration    = errors.New("пакет принадлежит другой политике Events")
	ErrBatchConflict = errors.New("ID пакета Events повторно использован с другим содержимым")
	ErrEventConflict = errors.New("запись Events повторно использована с другим содержимым")
)

const (
	maxStoredEvents   = 100000
	maxStoredReceipts = 10000
	maxStoredGaps     = 10000
	maxResultEvents   = 1000
)

// Store is independent of the inventory database. No personal token is saved:
// the policy's consent hash binds an explicit enable to one registration.
type Store struct {
	db        *sql.DB
	path      string
	backupMu  sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	now       func() time.Time
}

type StoredEvent struct {
	DeviceID int64 `json:"device_id"`
	Event
}

type StoredGap struct {
	DeviceID int64     `json:"device_id"`
	Channel  string    `json:"channel"`
	Reason   string    `json:"reason"`
	TimeUTC  time.Time `json:"time_utc"`
}

type DeviceStatus struct {
	Status
	LastReceived time.Time `json:"last_received"`
	LastContact  time.Time `json:"last_contact"`
	PolicySince  time.Time `json:"policy_since"`
	QueueSince   time.Time `json:"queue_since"`
	LastLoss     time.Time `json:"last_loss"`
}

type EventFilter struct {
	DeviceID int64
	Channel  string
	From     time.Time
	To       time.Time
	Limit    int
}

// Open creates the dedicated security-events.db at path. Cleanup runs both on
// receipt (to enforce count limits) and periodically (for idle retention).
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path, done: make(chan struct{}), now: time.Now}
	var formatID, formatVersion int
	if err = db.QueryRow(`PRAGMA application_id`).Scan(&formatID); err == nil {
		err = db.QueryRow(`PRAGMA user_version`).Scan(&formatVersion)
	}
	if err != nil || formatID != 0 && formatID != 1312900438 || formatVersion > 1 {
		db.Close()
		return nil, errors.New("неподдерживаемый формат хранилища Events")
	}
	statements := []string{
		"PRAGMA busy_timeout=3000",
		"PRAGMA auto_vacuum=INCREMENTAL",
		"PRAGMA journal_mode=WAL",
		"PRAGMA wal_autocheckpoint=64",
		"PRAGMA journal_size_limit=1048576",
		"PRAGMA max_page_count=196608",
		"PRAGMA secure_delete=ON",
		`CREATE TABLE IF NOT EXISTS events_policies(device_id INTEGER PRIMARY KEY CHECK(device_id>0), enabled INTEGER NOT NULL CHECK(enabled IN(0,1)), profile TEXT NOT NULL, generation TEXT NOT NULL, consent_hash TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS events_registrations(device_id INTEGER PRIMARY KEY CHECK(device_id>0), current_hash TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS events_status(device_id INTEGER PRIMARY KEY CHECK(device_id>0), payload BLOB NOT NULL, last_received INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS events_records(seq INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER NOT NULL, channel TEXT NOT NULL, stream_id TEXT NOT NULL, record_id TEXT NOT NULL, event_time INTEGER NOT NULL, received_at INTEGER NOT NULL, payload BLOB NOT NULL, payload_hash TEXT NOT NULL, UNIQUE(device_id,channel,stream_id,record_id))`,
		`CREATE INDEX IF NOT EXISTS events_records_received ON events_records(received_at,seq)`,
		`CREATE INDEX IF NOT EXISTS events_records_time ON events_records(event_time,seq)`,
		`CREATE INDEX IF NOT EXISTS events_records_device_time ON events_records(device_id,event_time,seq)`,
		`CREATE TABLE IF NOT EXISTS events_receipts(seq INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER NOT NULL, batch_id TEXT NOT NULL, payload_hash TEXT NOT NULL, received_at INTEGER NOT NULL, UNIQUE(device_id,batch_id))`,
		`CREATE INDEX IF NOT EXISTS events_receipts_received ON events_receipts(received_at,seq)`,
		`CREATE TABLE IF NOT EXISTS events_gaps(seq INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER NOT NULL, channel TEXT NOT NULL, reason TEXT NOT NULL, received_at INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS events_gaps_received ON events_gaps(received_at,seq)`,
	}
	for _, statement := range statements {
		if _, err = db.Exec(statement); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err = s.initFindings(); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.initDelivery(); err != nil {
		db.Close()
		return nil, err
	}
	if _, err = db.Exec(`PRAGMA application_id=1312900438; PRAGMA user_version=1`); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.cleanup(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0600)
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go s.cleaner(ctx)
	return s, nil
}

func (s *Store) cleaner(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			work, cancel := context.WithTimeout(ctx, 10*time.Second)
			_ = s.cleanup(work)
			cancel()
		}
	}
}

func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		<-s.done
		_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		s.closeErr = s.db.Close()
	})
	return s.closeErr
}

func tokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func randomGeneration() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func validIdentity(deviceID int64, token string) bool {
	return deviceID > 0 && len(token) > 0 && len(token) <= 256
}

func readPolicy(ctx context.Context, tx *sql.Tx, deviceID int64) (Policy, string, error) {
	p := Policy{Profile: "system"}
	var hash string
	err := tx.QueryRowContext(ctx, `SELECT enabled,profile,generation,consent_hash FROM events_policies WHERE device_id=?`, deviceID).Scan(&p.Enabled, &p.Profile, &p.Generation, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return p, "", nil
	}
	return p, hash, err
}

// boundPolicy invalidates consent permanently when a changed registration is
// observed and erases data belonging to the previous registration. A device ID
// may be reused after restoring the inventory database. The observed hash is
// separate from consent so that repeat disabled polls neither erase new health
// nor hide the registration-change notice.
func boundPolicy(ctx context.Context, tx *sql.Tx, deviceID int64, token string) (Policy, error) {
	p, hash, err := readPolicy(ctx, tx, deviceID)
	if err != nil {
		return p, err
	}
	var previousHash string
	err = tx.QueryRowContext(ctx, `SELECT current_hash FROM events_registrations WHERE device_id=?`, deviceID).Scan(&previousHash)
	if errors.Is(err, sql.ErrNoRows) {
		previousHash = hash
	} else if err != nil {
		return p, err
	}
	currentHash := tokenHash(token)
	if previousHash != "" && previousHash != currentHash || p.Enabled && hash != currentHash {
		p.Enabled = false
		if p.Generation != "" {
			p.Generation, err = randomGeneration()
			if err != nil {
				return p, err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE events_policies SET enabled=0,generation=? WHERE device_id=?`, p.Generation, deviceID); err != nil {
				return p, err
			}
		}
		for _, table := range []string{"events_records", "events_receipts", "events_gaps", "events_status", "events_delivery", "events_findings", "events_rule_samples", "events_finding_evidence", "events_finding_comments", "events_rule_exceptions"} {
			if _, err = tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE device_id=?`, deviceID); err != nil {
				return p, err
			}
		}
		if err = writeStatus(ctx, tx, deviceID, DeviceStatus{Status: Status{Generation: p.Generation, State: "disabled"}}); err != nil {
			return p, err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events_registrations(device_id,current_hash)VALUES(?,?) ON CONFLICT(device_id)DO UPDATE SET current_hash=excluded.current_hash`, deviceID, currentHash)
	return p, err
}

func (s *Store) Policy(ctx context.Context, deviceID int64, token string) (Policy, error) {
	// Empty means registration was revoked, which must revoke consent too.
	if deviceID <= 0 || len(token) > 256 {
		return Policy{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Policy{}, err
	}
	defer tx.Rollback()
	p, err := boundPolicy(ctx, tx, deviceID, token)
	if err != nil {
		return p, err
	}
	return p, tx.Commit()
}

func (s *Store) RegistrationChanged(ctx context.Context, deviceID int64, token string) (bool, error) {
	if deviceID <= 0 || len(token) > 256 {
		return false, ErrInvalid
	}
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT consent_hash FROM events_policies WHERE device_id=?`, deviceID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return hash != "" && hash != tokenHash(token), err
}

func (s *Store) SetPolicy(ctx context.Context, deviceID int64, token string, enabled bool, profile string) (Policy, error) {
	if deviceID <= 0 || len(token) > 256 || enabled && token == "" || profile != "system" && profile != "security" {
		return Policy{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Policy{}, err
	}
	defer tx.Rollback()
	if _, err = boundPolicy(ctx, tx, deviceID, token); err != nil {
		return Policy{}, err
	}
	p, hash, err := readPolicy(ctx, tx, deviceID)
	if err != nil {
		return p, err
	}
	newHash := hash
	if enabled {
		newHash = tokenHash(token)
	}
	changed := p.Generation == "" || p.Enabled != enabled || p.Profile != profile || enabled && hash != newHash
	if changed {
		p.Generation, err = randomGeneration()
		if err != nil {
			return p, err
		}
	}
	p.Enabled, p.Profile = enabled, profile
	if _, err = tx.ExecContext(ctx, `INSERT INTO events_policies(device_id,enabled,profile,generation,consent_hash)VALUES(?,?,?,?,?) ON CONFLICT(device_id)DO UPDATE SET enabled=excluded.enabled,profile=excluded.profile,generation=excluded.generation,consent_hash=excluded.consent_hash`, deviceID, enabled, profile, p.Generation, newHash); err != nil {
		return p, err
	}
	if changed {
		if _, err = tx.ExecContext(ctx, `INSERT INTO events_delivery(device_id,generation,policy_at,last_poll,queue_since,loss_at)VALUES(?,?,?,0,0,0) ON CONFLICT(device_id)DO UPDATE SET generation=excluded.generation,policy_at=excluded.policy_at,last_poll=0,queue_since=0,loss_at=0`, deviceID, p.Generation, s.now().UTC().UnixMilli()); err != nil {
			return p, err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM events_rule_samples WHERE device_id=?`, deviceID); err != nil {
			return p, err
		}
		status, readErr := readStatus(ctx, tx, deviceID)
		if readErr != nil {
			return p, readErr
		}
		state := "disabled"
		if enabled {
			state = "pending"
		}
		status.Status = Status{Generation: p.Generation, State: state, Dropped: status.Dropped}
		status.LastReceived = time.Time{}
		if err = writeStatus(ctx, tx, deviceID, status); err != nil {
			return p, err
		}
	}
	return p, tx.Commit()
}

func readStatus(ctx context.Context, tx *sql.Tx, deviceID int64) (DeviceStatus, error) {
	status := DeviceStatus{Status: Status{State: "disabled"}}
	var payload []byte
	var received int64
	err := tx.QueryRowContext(ctx, `SELECT payload,last_received FROM events_status WHERE device_id=?`, deviceID).Scan(&payload, &received)
	if errors.Is(err, sql.ErrNoRows) {
		return status, nil
	}
	if err != nil {
		return status, err
	}
	if len(payload) > 4096 || json.Unmarshal(payload, &status.Status) != nil {
		return status, errors.New("повреждено состояние Events")
	}
	if received != 0 {
		status.LastReceived = time.UnixMilli(received).UTC()
	}
	var contact, policy, queue, loss int64
	err = tx.QueryRowContext(ctx, `SELECT last_poll,policy_at,queue_since,loss_at FROM events_delivery WHERE device_id=?`, deviceID).Scan(&contact, &policy, &queue, &loss)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return status, err
	}
	status.LastContact, status.PolicySince, status.QueueSince, status.LastLoss = deliveryTime(contact), deliveryTime(policy), deliveryTime(queue), deliveryTime(loss)
	return status, nil
}

func writeStatus(ctx context.Context, tx *sql.Tx, deviceID int64, status DeviceStatus) error {
	payload, err := json.Marshal(status.Status)
	if err != nil {
		return err
	}
	if len(payload) > 4096 {
		return ErrInvalid
	}
	var received int64
	if !status.LastReceived.IsZero() {
		received = status.LastReceived.UnixMilli()
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events_status(device_id,payload,last_received)VALUES(?,?,?) ON CONFLICT(device_id)DO UPDATE SET payload=excluded.payload,last_received=excluded.last_received`, deviceID, payload, received)
	return err
}

// UpdateStatus accepts a first/default-off poll and stale generations so that a
// poll can always deliver a new policy. Stale health cannot overwrite new state.
func (s *Store) UpdateStatus(ctx context.Context, deviceID int64, token string, status Status) error {
	if !validIdentity(deviceID, token) || validateStatus(status, s.now()) != nil {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := boundPolicy(ctx, tx, deviceID, token)
	if err != nil {
		return err
	}
	previous, err := readStatus(ctx, tx, deviceID)
	if err != nil {
		return err
	}
	dropped := max(previous.Dropped, status.Dropped)
	oldDropped := previous.Dropped
	if !p.Enabled {
		if status.Generation != "" && status.Generation != p.Generation {
			// Old registration/generation health cannot revive its counters.
			dropped = previous.Dropped
		}
		previous.Status = Status{Generation: p.Generation, State: "disabled", Dropped: dropped}
	} else if status.Generation == p.Generation {
		for _, channel := range status.Channels {
			if !profileChannel(p.Profile, channel.Channel) {
				return ErrInvalid
			}
		}
		previous.Status = status
		previous.Dropped = dropped
	} else {
		previous.Dropped = dropped
	}
	if err = writeStatus(ctx, tx, deviceID, previous); err != nil {
		return err
	}
	if err = recordPoll(ctx, tx, deviceID, p, previous, oldDropped, s.now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetStatus(ctx context.Context, deviceID int64) (DeviceStatus, error) {
	if deviceID <= 0 {
		return DeviceStatus{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceStatus{}, err
	}
	defer tx.Rollback()
	return readStatus(ctx, tx, deviceID)
}

func (s *Store) Status(ctx context.Context, deviceID int64) (Status, error) {
	status, err := s.GetStatus(ctx, deviceID)
	return status.Status, err
}

// AcceptBatch returns success only after the transaction commits. A retry is
// checked before new writes, and differing data under a used ID is rejected.
func (s *Store) AcceptBatch(ctx context.Context, deviceID int64, token string, batch Batch) error {
	now := s.now().UTC()
	if !validIdentity(deviceID, token) {
		return ErrInvalid
	}
	payload, err := validateBatch(batch, now)
	if err != nil {
		return err
	}
	hash := tokenHash(string(payload))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := boundPolicy(ctx, tx, deviceID, token)
	if err != nil {
		return err
	}
	if !p.Enabled {
		// Persist observed registration invalidation, but never ACK this batch.
		if err = tx.Commit(); err != nil {
			return err
		}
		return ErrDisabled
	}
	if batch.Generation != p.Generation {
		return ErrGeneration
	}
	for _, event := range batch.Events {
		if !profileChannel(p.Profile, event.Channel) {
			return ErrInvalid
		}
	}
	for _, gap := range batch.Gaps {
		if !profileChannel(p.Profile, gap.Channel) {
			return ErrInvalid
		}
	}
	for _, channel := range batch.Health {
		if !profileChannel(p.Profile, channel.Channel) {
			return ErrInvalid
		}
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT payload_hash FROM events_receipts WHERE device_id=? AND batch_id=?`, deviceID, batch.ID).Scan(&existing)
	if err == nil {
		if existing != hash {
			return ErrBatchConflict
		}
		status, statusErr := readStatus(ctx, tx, deviceID)
		if statusErr != nil {
			return statusErr
		}
		status.LastReceived = now
		if err = writeStatus(ctx, tx, deviceID, status); err != nil {
			return err
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	fresh := []observedEvent{}
	for _, event := range batch.Events {
		encoded, _ := json.Marshal(event)
		eventHash := tokenHash(string(encoded))
		record := strconv.FormatUint(event.RecordID, 10)
		err = tx.QueryRowContext(ctx, `SELECT payload_hash FROM events_records WHERE device_id=? AND channel=? AND stream_id=? AND record_id=?`, deviceID, event.Channel, event.StreamID, record).Scan(&existing)
		if err == nil {
			if existing != eventHash {
				return ErrEventConflict
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		result, insertErr := tx.ExecContext(ctx, `INSERT INTO events_records(device_id,channel,stream_id,record_id,event_time,received_at,payload,payload_hash)VALUES(?,?,?,?,?,?,?,?)`, deviceID, event.Channel, event.StreamID, record, event.TimeUTC.UnixMilli(), now.UnixMilli(), encoded, eventHash)
		if insertErr != nil {
			return insertErr
		}
		seq, sequenceErr := result.LastInsertId()
		if sequenceErr != nil {
			return sequenceErr
		}
		fresh = append(fresh, observedEvent{seq: seq, event: event})
	}
	if err = detectFindings(ctx, tx, deviceID, fresh, now); err != nil {
		return err
	}
	for _, gap := range batch.Gaps {
		if _, err = tx.ExecContext(ctx, `INSERT INTO events_gaps(device_id,channel,reason,received_at)VALUES(?,?,?,?)`, deviceID, gap.Channel, gap.Reason, now.UnixMilli()); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO events_receipts(device_id,batch_id,payload_hash,received_at)VALUES(?,?,?,?)`, deviceID, batch.ID, hash, now.UnixMilli()); err != nil {
		return err
	}
	status, err := readStatus(ctx, tx, deviceID)
	if err != nil {
		return err
	}
	status.Generation = p.Generation
	oldDropped := status.Dropped
	status.Dropped = max(status.Dropped, batch.Dropped)
	status.LastReceived = now
	if len(batch.Health) > 0 {
		status.Channels = batch.Health
		status.State = "collecting"
		for _, health := range batch.Health {
			if health.State == "error" {
				status.State = "error"
			}
		}
	}
	if err = writeStatus(ctx, tx, deviceID, status); err != nil {
		return err
	}
	if status.Dropped > oldDropped {
		if _, err = tx.ExecContext(ctx, `UPDATE events_delivery SET loss_at=? WHERE device_id=?`, now.UnixMilli(), deviceID); err != nil {
			return err
		}
	}
	if err = cleanupTx(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Events(ctx context.Context, deviceID int64, limit int) ([]StoredEvent, error) {
	return s.EventsFiltered(ctx, EventFilter{DeviceID: deviceID, Limit: limit})
}

func (s *Store) EventsFiltered(ctx context.Context, filter EventFilter) ([]StoredEvent, error) {
	if filter.DeviceID < 0 || filter.Channel != "" && !profileChannel("security", filter.Channel) || !filter.From.IsZero() && !filter.To.IsZero() && filter.From.After(filter.To) {
		return nil, ErrInvalid
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, maxResultEvents)
	query := `SELECT device_id,payload FROM events_records WHERE received_at>=?`
	args := []any{s.now().Add(-RetentionDays * 24 * time.Hour).UnixMilli()}
	if filter.DeviceID != 0 {
		query += ` AND device_id=?`
		args = append(args, filter.DeviceID)
	}
	if filter.Channel != "" {
		query += ` AND channel=?`
		args = append(args, filter.Channel)
	}
	if !filter.From.IsZero() {
		query += ` AND event_time>=?`
		args = append(args, filter.From.UnixMilli())
	}
	if !filter.To.IsZero() {
		query += ` AND event_time<=?`
		args = append(args, filter.To.UnixMilli())
	}
	query += ` ORDER BY event_time DESC,seq DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []StoredEvent{}
	for rows.Next() {
		var event StoredEvent
		var payload []byte
		if err = rows.Scan(&event.DeviceID, &payload); err != nil {
			return nil, err
		}
		if len(payload) > 4096 || json.Unmarshal(payload, &event.Event) != nil {
			return nil, errors.New("повреждена запись Events")
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *Store) Gaps(ctx context.Context, deviceID int64, limit int) ([]StoredGap, error) {
	if deviceID < 0 {
		return nil, ErrInvalid
	}
	if limit <= 0 {
		limit = 100
	}
	limit = min(limit, maxResultEvents)
	query := `SELECT device_id,channel,reason,received_at FROM events_gaps WHERE received_at>=?`
	args := []any{s.now().Add(-RetentionDays * 24 * time.Hour).UnixMilli()}
	if deviceID != 0 {
		query += ` AND device_id=?`
		args = append(args, deviceID)
	}
	query += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []StoredGap{}
	for rows.Next() {
		var gap StoredGap
		var stamp int64
		if err = rows.Scan(&gap.DeviceID, &gap.Channel, &gap.Reason, &stamp); err != nil {
			return nil, err
		}
		gap.TimeUTC = time.UnixMilli(stamp).UTC()
		result = append(result, gap)
	}
	return result, rows.Err()
}

func (s *Store) DeleteDevice(ctx context.Context, deviceID int64) error {
	if deviceID <= 0 {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"events_policies", "events_registrations", "events_status", "events_delivery", "events_records", "events_receipts", "events_gaps", "events_findings", "events_rule_samples", "events_finding_evidence", "events_finding_comments", "events_rule_exceptions"} {
		if _, err = tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE device_id=?`, deviceID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func cleanupTx(ctx context.Context, tx *sql.Tx, now time.Time) error {
	cutoff := now.Add(-RetentionDays * 24 * time.Hour).UnixMilli()
	for _, table := range []struct {
		name  string
		limit int
	}{{"events_records", maxStoredEvents}, {"events_receipts", maxStoredReceipts}, {"events_gaps", maxStoredGaps}} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table.name+` WHERE received_at<?`, cutoff); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table.name).Scan(&count); err != nil {
			return err
		}
		if count > table.limit {
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+table.name+` WHERE seq IN(SELECT seq FROM `+table.name+` ORDER BY seq LIMIT ?)`, count-table.limit); err != nil {
				return err
			}
		}
	}
	return cleanupFindings(ctx, tx, now)
}

func (s *Store) cleanup(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = cleanupTx(ctx, tx, s.now()); err != nil {
		return fmt.Errorf("очистка Events: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if _, err = s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `PRAGMA incremental_vacuum(256)`)
	return err
}
