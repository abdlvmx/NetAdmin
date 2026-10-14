//go:build securityevents

package securityevents

import (
	"context"
	"strings"
	"time"
)

func appendDeviceScope(query string, args []any, devices []int64) (string, []any, error) {
	if devices == nil {
		return query, args, nil
	}
	if len(devices) == 0 {
		return query + " AND 0=1", args, nil
	}
	if len(devices) > 20000 {
		return "", nil, ErrInvalid
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(devices)), ",")
	for _, id := range devices {
		if id <= 0 {
			return "", nil, ErrInvalid
		}
		args = append(args, id)
	}
	return query + " AND device_id IN (" + marks + ")", args, nil
}
func (s *Store) FindingDevice(ctx context.Context, id int64) (int64, error) {
	var device int64
	err := s.db.QueryRowContext(ctx, "SELECT device_id FROM events_findings WHERE id=? AND observed_at>=?", id, s.now().Add(-RetentionDays*24*time.Hour).UnixMilli()).Scan(&device)
	return device, err
}
