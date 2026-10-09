//go:build securityevents

package securityevents

import (
	"context"
	"database/sql"
	"time"
)

const DeliveryTimeout = 3 * time.Minute
const QueueTimeout = 10 * time.Minute

type DeliveryHealth struct {
	Code, Level, Title, Detail, NextStep string
	Since                                time.Time
}

func deliveryTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func (s *Store) initDelivery() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS events_delivery(device_id INTEGER PRIMARY KEY, generation TEXT NOT NULL, policy_at INTEGER NOT NULL, last_poll INTEGER NOT NULL DEFAULT 0, queue_since INTEGER NOT NULL DEFAULT 0, loss_at INTEGER NOT NULL DEFAULT 0)`)
	if err != nil {
		return err
	}
	// Give existing enabled devices a grace interval after this migration.
	_, err = s.db.Exec(`INSERT OR IGNORE INTO events_delivery(device_id,generation,policy_at) SELECT device_id,generation,? FROM events_policies`, s.now().UTC().UnixMilli())
	return err
}

func recordPoll(ctx context.Context, tx *sql.Tx, id int64, p Policy, status DeviceStatus, oldDropped uint64, now time.Time) error {
	queue, loss := status.QueueSince, status.LastLoss
	if !p.Enabled || status.QueueBytes == 0 {
		queue = time.Time{}
	} else if queue.IsZero() {
		queue = now
	}
	if status.Dropped > oldDropped {
		loss = now
	}
	ms := func(t time.Time) int64 {
		if t.IsZero() {
			return 0
		}
		return t.UnixMilli()
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO events_delivery(device_id,generation,policy_at,last_poll,queue_since,loss_at)VALUES(?,?,?,?,?,?) ON CONFLICT(device_id)DO UPDATE SET last_poll=excluded.last_poll,queue_since=excluded.queue_since,loss_at=excluded.loss_at`, id, p.Generation, ms(now), ms(now), ms(queue), ms(loss))
	return err
}

// AssessDelivery uses server receipt times for connectivity, never the timestamp
// of the last selected event. Empty logs still have polls and collection health.
// LastCollected is agent-reported and is described as such in the interface.
func AssessDelivery(p Policy, s DeviceStatus, now time.Time) DeliveryHealth {
	if !p.Enabled {
		return DeliveryHealth{Code: "disabled", Level: "info", Title: "Сбор выключен"}
	}
	base := s.PolicySince
	if base.IsZero() {
		base = now
	}
	contact := s.LastContact
	if s.LastReceived.After(contact) {
		contact = s.LastReceived
	}
	if contact.IsZero() {
		if now.Sub(base) > DeliveryTimeout {
			return DeliveryHealth{Code: "no_contact", Level: "error", Title: "Агент не подтвердил связь Events", Detail: "После включения сбора сервер не получил ни проверки политики, ни пакета.", NextStep: "Проверьте службу агента, адрес HTTPS и доверие к сертификату на ПК.", Since: base}
		}
		return DeliveryHealth{Code: "pending", Level: "info", Title: "Ожидание агента", Detail: "На первый контакт отведено 3 минуты.", Since: base}
	}
	if now.Sub(contact) > DeliveryTimeout {
		return DeliveryHealth{Code: "stale", Level: "error", Title: "Нет связи Events", Detail: "Сервер более 3 минут не получает подписанные запросы Events от этого ПК. Прежний статус сбора устарел.", NextStep: "Проверьте службу агента, доступность сервера и сертификат HTTPS. Причина без связи неизвестна.", Since: contact}
	}
	if s.Generation != p.Generation || s.State == "pending" || s.State == "disabled" {
		level := "info"
		if now.Sub(base) > DeliveryTimeout {
			level = "warning"
		}
		return DeliveryHealth{Code: "pending", Level: level, Title: "Агент применяет настройки", Detail: "Связь есть, но работа с текущей политикой ещё не подтверждена.", NextStep: "Если ожидание продолжается, проверьте агент и его журналы.", Since: base}
	}
	if s.State == "error" {
		return DeliveryHealth{Code: "collector_error", Level: "error", Title: "Ошибка чтения или очереди", Detail: "Агент сообщил об ошибке сбора. Подробности по каналам указаны ниже.", NextStep: "Проверьте доступ к выбранным журналам и свободное место на ПК.", Since: contact}
	}
	if s.State == "paused" {
		return DeliveryHealth{Code: "paused", Level: "warning", Title: "Доставка приостановлена", Detail: "Агент сообщает о приостановке. Новые чтения ждут свежей политики и подтверждения пакетов.", NextStep: "Проверьте указанную агентом ошибку и доступность сервера.", Since: contact}
	}
	if now.Sub(base) > DeliveryTimeout && (s.LastCollected.IsZero() || now.Sub(s.LastCollected) > DeliveryTimeout) {
		return DeliveryHealth{Code: "not_collecting", Level: "warning", Title: "Чтение журналов не подтверждено", Detail: "Запросы Events приходят, но агент более 3 минут не сообщает об успешном чтении.", NextStep: "Проверьте журналы агента, права чтения и часы ПК.", Since: s.LastCollected}
	}
	if s.QueueBytes > 0 && !s.QueueSince.IsZero() && now.Sub(s.QueueSince) > QueueTimeout && (s.LastReceived.IsZero() || now.Sub(s.LastReceived) > QueueTimeout) {
		return DeliveryHealth{Code: "queue_stalled", Level: "warning", Title: "Очередь не доставляется", Detail: "События ожидают отправки более 10 минут; новых подтверждённых пакетов нет.", NextStep: "Проверьте свободное место и ошибки приёма на сервере.", Since: s.QueueSince}
	}
	if !s.LastLoss.IsZero() && now.Sub(s.LastLoss) < 24*time.Hour {
		return DeliveryHealth{Code: "loss", Level: "warning", Title: "За последние сутки были пропуски", Detail: "Счётчик пропущенных событий вырос. Накопленное число показано ниже; это не полная запись журналов.", NextStep: "Проверьте очередь и нагрузку на агент. Устранённые пропуски исчезнут из предупреждений через сутки.", Since: s.LastLoss}
	}
	if s.QueueBytes > 0 {
		return DeliveryHealth{Code: "queued", Level: "ok", Title: "Доставка продолжается", Detail: "Связь свежая; в очереди есть события для отправки."}
	}
	return DeliveryHealth{Code: "healthy", Level: "ok", Title: "Сбор и связь работают", Detail: "Связь и чтение подтверждены. Отсутствие выбранных событий не считается неисправностью."}
}
