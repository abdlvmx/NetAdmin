package handlers

import (
	"fmt"
	"time"

	"netadmin/internal/netscan"
	"netadmin/internal/notify"
)

const downThreshold = 3 // подряд неответов до объявления «связь потеряна»

// CheckCritical пингует критически важные устройства и ведёт инциденты
// доступности: 3 неответа подряд → инцидент + email; восстановление →
// авто-закрытие инцидента + уведомление. Вызывается по таймеру (~раз в минуту).
func (a *App) CheckCritical() {
	type dev struct {
		id        int64
		host, ip  string
		streak    int
		downSince string
	}
	var list []dev
	rows, err := a.DB.Query(`SELECT id, hostname, COALESCE(ip_address,''),
		COALESCE(down_streak,0), COALESCE(down_since,'')
		FROM devices WHERE critical=1 AND COALESCE(ip_address,'')<>''`)
	if err != nil {
		return
	}
	for rows.Next() {
		var d dev
		if rows.Scan(&d.id, &d.host, &d.ip, &d.streak, &d.downSince) == nil {
			list = append(list, d)
		}
	}
	rows.Close()

	for _, d := range list {
		if netscan.PingHost(d.ip) {
			a.DB.Exec("UPDATE devices SET status='online', last_seen=datetime('now'), down_streak=0, down_since=NULL WHERE id=?", d.id)
			if d.downSince != "" { // было в дауне → восстановление
				dur := downtimeText(d.downSince)
				a.DB.Exec(`UPDATE events SET status='resolved'
					WHERE hostname=? AND category='uptime' AND status IN ('new','ack')`, d.host)
				a.DB.Exec(`INSERT INTO events (hostname, source, event_id, severity, category, message)
					VALUES (?, 'correlation', 0, 'info', 'uptime', ?)`,
					d.host, fmt.Sprintf("Связь с %s восстановлена (была недоступна %s)", d.host, dur))
				notify.Message(fmt.Sprintf("✅ NetAdmin: связь с %s восстановлена (была недоступна %s)", d.host, dur))
			}
			continue
		}

		// нет ответа
		streak := d.streak + 1
		if streak == downThreshold && d.downSince == "" {
			a.DB.Exec("UPDATE devices SET status='offline', down_streak=?, down_since=datetime('now') WHERE id=?", streak, d.id)
			msg := fmt.Sprintf("Связь с критичным устройством %s (%s) потеряна!", d.host, d.ip)
			a.DB.Exec(`INSERT INTO events (hostname, source, event_id, severity, category, message)
				VALUES (?, 'correlation', 0, 'critical', 'uptime', ?)`, d.host, msg)
			notify.CriticalEvent(d.host, msg)
		} else {
			a.DB.Exec("UPDATE devices SET status='offline', down_streak=? WHERE id=?", streak, d.id)
		}
	}
}

// downtimeText — человекочитаемая длительность простоя от момента downSince.
func downtimeText(downSince string) string {
	t, err := time.Parse("2006-01-02 15:04:05", downSince)
	if err != nil {
		return "—"
	}
	d := time.Since(t.UTC())
	if d < time.Minute {
		return fmt.Sprintf("%d сек", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	}
	return fmt.Sprintf("%d ч %d мин", int(d.Hours()), int(d.Minutes())%60)
}
