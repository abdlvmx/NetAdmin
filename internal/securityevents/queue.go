//go:build securityevents

package securityevents

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

type Cursor struct {
	Bookmark string `json:"bookmark"`
	StreamID string `json:"stream_id"`
}
type QueueState struct {
	ServerURL string            `json:"server_url"`
	DeviceID  int64             `json:"device_id"`
	Policy    Policy            `json:"policy"`
	Cursors   map[string]Cursor `json:"cursors"`
	Status    Status            `json:"status"`
}

type Queue struct {
	db         *sql.DB
	maxBytes   int64
	maxBatches int
}

// OpenQueue keeps bookmarks and unacknowledged batches in one transaction.
// A crash cannot advance a cursor without preserving its selected events.
func OpenQueue(path string) (*Queue, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	q := &Queue{db: db, maxBytes: MaxQueueBytes, maxBatches: 512}
	for _, s := range []string{"PRAGMA busy_timeout=3000", "PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL", "PRAGMA wal_autocheckpoint=64", "PRAGMA journal_size_limit=1048576", "PRAGMA max_page_count=9216", "PRAGMA secure_delete=ON", `CREATE TABLE IF NOT EXISTS queue_state(id INTEGER PRIMARY KEY CHECK(id=1),payload BLOB NOT NULL)`, `CREATE TABLE IF NOT EXISTS queue_batches(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,payload BLOB NOT NULL,size INTEGER NOT NULL)`} {
		if _, err = db.Exec(s); err != nil {
			db.Close()
			return nil, err
		}
	}
	// SQLite file modes do not restrict NTFS ACLs; the agent directory must.
	_ = os.Chmod(path, 0600)
	return q, nil
}

func (q *Queue) Close() error { return q.db.Close() }

func (q *Queue) State() (QueueState, error) {
	var s QueueState
	var b []byte
	err := q.db.QueryRow(`SELECT payload FROM queue_state WHERE id=1`).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		s.Cursors = map[string]Cursor{}
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if len(b) > 128<<10 || json.Unmarshal(b, &s) != nil {
		return s, errors.New("повреждено состояние очереди Events")
	}
	if s.Cursors == nil {
		s.Cursors = map[string]Cursor{}
	}
	return s, nil
}

func (q *Queue) Bytes() (int64, error) {
	var n int64
	err := q.db.QueryRow(`SELECT COALESCE(SUM(size),0) FROM queue_batches`).Scan(&n)
	return n, err
}

func writeQueueState(ctx context.Context, tx *sql.Tx, s QueueState) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(b) > 128<<10 {
		return errors.New("состояние Events превышает предел")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO queue_state(id,payload)VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload`, b)
	return err
}

// Commit preserves batches and cursor changes atomically. When capacity is
// reached, it explicitly counts selected events dropped and still advances.
func (q *Queue) Commit(ctx context.Context, s QueueState, batches []Batch) (QueueState, error) {
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return s, err
	}
	defer tx.Rollback()
	var used int64
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size),0),COUNT(*) FROM queue_batches`).Scan(&used, &count); err != nil {
		return s, err
	}
	for _, b := range batches {
		if b.ID == "" || b.Generation != s.Policy.Generation || len(b.Events) > MaxBatchEvents {
			return s, errors.New("некорректный пакет Events")
		}
		payload, marshalErr := json.Marshal(b)
		if marshalErr != nil {
			return s, marshalErr
		}
		if len(payload) > MaxBatchBytes-1024 {
			return s, errors.New("пакет Events превышает предел")
		}
		if used+int64(len(payload)) > q.maxBytes || count >= q.maxBatches {
			s.Status.Dropped += uint64(len(b.Events))
			s.Status.Error = "Очередь заполнена; новые выбранные события пропущены."
			continue
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO queue_batches(id,payload,size)VALUES(?,?,?)`, b.ID, payload, len(payload)); err != nil {
			return s, err
		}
		used += int64(len(payload))
		count++
	}
	s.Status.QueueBytes = used
	if err = writeQueueState(ctx, tx, s); err != nil {
		return s, err
	}
	if err = tx.Commit(); err != nil {
		return s, err
	}
	return s, nil
}

func (q *Queue) Oldest() (Batch, bool, error) {
	var batch Batch
	var b []byte
	err := q.db.QueryRow(`SELECT payload FROM queue_batches ORDER BY seq LIMIT 1`).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return batch, false, nil
	}
	if err != nil {
		return batch, false, err
	}
	if len(b) > MaxBatchBytes || json.Unmarshal(b, &batch) != nil {
		return batch, false, errors.New("повреждён пакет в очереди Events")
	}
	return batch, true, nil
}

func (q *Queue) Acknowledge(ctx context.Context, id string) error {
	_, err := q.db.ExecContext(ctx, `DELETE FROM queue_batches WHERE id=?`, id)
	return err
}

func (q *Queue) Reset(ctx context.Context, s QueueState) (QueueState, error) {
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return s, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT payload FROM queue_batches`)
	if err != nil {
		return s, err
	}
	for rows.Next() {
		var b []byte
		var batch Batch
		if err = rows.Scan(&b); err != nil {
			break
		}
		if json.Unmarshal(b, &batch) != nil {
			err = errors.New("повреждена очередь при отключении Events")
			break
		}
		s.Status.Dropped += uint64(len(batch.Events))
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return s, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM queue_batches`); err != nil {
		return s, err
	}
	s.Cursors = map[string]Cursor{}
	s.Status.QueueBytes = 0
	if err = writeQueueState(ctx, tx, s); err != nil {
		return s, err
	}
	if err = tx.Commit(); err != nil {
		return s, err
	}
	_, _ = q.db.Exec(`PRAGMA incremental_vacuum(256)`)
	return s, nil
}

// SplitBatches leaves room for the signed envelope and uses stable IDs in the
// durable queue. Every retry sends the same batch ID with a fresh request nonce.
func SplitBatches(generation string, events []Event, gaps []Gap, status Status, newID func() string) ([]Batch, error) {
	result := []Batch{}
	b := Batch{ID: newID(), Generation: generation, Events: []Event{}, Gaps: gaps, Health: status.Channels, Dropped: status.Dropped}
	for _, event := range events {
		single, err := json.Marshal(event)
		if err != nil || len(single) > 4096 {
			return nil, fmt.Errorf("слишком большое событие Events")
		}
		b.Events = append(b.Events, event)
		encoded, err := json.Marshal(b)
		if err != nil {
			return nil, err
		}
		if len(b.Events) > MaxBatchEvents || len(encoded) > MaxBatchBytes-1024 {
			b.Events = b.Events[:len(b.Events)-1]
			result = append(result, b)
			b = Batch{ID: newID(), Generation: generation, Events: []Event{event}, Dropped: status.Dropped}
		}
	}
	if len(b.Events) > 0 || len(b.Gaps) > 0 {
		result = append(result, b)
	}
	return result, nil
}
