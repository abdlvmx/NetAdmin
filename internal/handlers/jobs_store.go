package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"netadmin/internal/auth"
)

type taskSpec struct {
	Kind, Payload, Label string
	PackageID            int64
}
type queuedJob struct {
	ID    int64
	Tasks []int64
}

func (a *App) enqueueJob(ctx context.Context, ids []int64, spec taskSpec, actor int64) (queuedJob, error) {
	tx, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return queuedJob{}, err
	}
	defer tx.Rollback()
	job, err := a.enqueueJobTx(ctx, tx, ids, spec, actor, 0, nil)
	if err != nil {
		return queuedJob{}, err
	}
	if err = tx.Commit(); err != nil {
		return queuedJob{}, err
	}
	return job, nil
}
func (a *App) enqueueJobTx(ctx context.Context, tx *sql.Tx, ids []int64, spec taskSpec, actor, parent int64, sources []int64) (queuedJob, error) {
	if len(ids) == 0 || len(ids) > 5000 || (sources != nil && len(sources) != len(ids)) {
		return queuedJob{}, errors.New("invalid job targets")
	}
	seen := map[int64]bool{}
	var targets, retryIDs []int64
	for i, id := range ids {
		if id <= 0 {
			return queuedJob{}, errors.New("invalid job target")
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		targets = append(targets, id)
		if sources != nil {
			retryIDs = append(retryIDs, sources[i])
		} else {
			retryIDs = append(retryIDs, 0)
		}
	}
	// Validate all targets inside the same transaction, including unrestricted
	// callers. A stale selection never produces a partly queued batch.
	if err := a.validateScopedTx(ctx, tx, targets); err != nil {
		return queuedJob{}, err
	}
	result, err := tx.ExecContext(ctx, "INSERT INTO agent_jobs(kind,label,created_by,target_count,parent_id) VALUES(?,?,?,?,?)", spec.Kind, spec.Label, actor, len(targets), parent)
	if err != nil {
		return queuedJob{}, err
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		return queuedJob{}, err
	}
	job := queuedJob{ID: jobID}
	for i, id := range targets {
		result, err = tx.ExecContext(ctx, `INSERT INTO agent_tasks(device_id,kind,payload,label,status,created_by,package_id,job_id,retry_of) VALUES(?,?,?,?,'pending',?,?,?,?)`, id, spec.Kind, spec.Payload, spec.Label, actor, spec.PackageID, jobID, retryIDs[i])
		if err != nil {
			return queuedJob{}, err
		}
		task, err := result.LastInsertId()
		if err != nil {
			return queuedJob{}, err
		}
		job.Tasks = append(job.Tasks, task)
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_log(user_id,action,target,detail) VALUES(?,'job_create',?,?)", actor, fmt.Sprint(jobID), fmt.Sprintf("kind=%s targets=%d parent=%d", spec.Kind, len(targets), parent)); err != nil {
		return queuedJob{}, err
	}
	return job, nil
}

func jobCanRepeat(u *auth.User, kind string) bool {
	if !u.CanWrite() {
		return false
	}
	switch kind {
	case "command", "check", "reboot", "shutdown", "logoff":
		return true
	case "install", "selfupdate":
		return u.IsAdmin()
	}
	return false
}
