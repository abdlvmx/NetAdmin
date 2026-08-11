// Package snmp — тонкая обёртка над gosnmp (SNMPv2c) для опроса сетевого
// оборудования (свитчи/роутеры/ИБП/сетевые принтеры). Это мониторинг состояния,
// не средство защиты информации.
package snmp

import (
	"strings"
	"time"

	g "github.com/gosnmp/gosnmp"
)

// Стандартные OID (MIB-II, UPS-MIB, Printer-MIB).
const (
	OIDSysDescr     = "1.3.6.1.2.1.1.1.0"
	OIDSysUptime    = "1.3.6.1.2.1.1.3.0"
	OIDSysName      = "1.3.6.1.2.1.1.5.0"
	OIDIfOperStatus = "1.3.6.1.2.1.2.2.1.8"
	OIDIfDescr      = "1.3.6.1.2.1.2.2.1.2"
	OIDIfSpeed      = "1.3.6.1.2.1.2.2.1.5"
	OIDIfInOctets   = "1.3.6.1.2.1.2.2.1.10"
	OIDIfOutOctets  = "1.3.6.1.2.1.2.2.1.16"

	// UPS-MIB (RFC 1628)
	OIDUpsBatteryStatus  = "1.3.6.1.2.1.33.1.2.1.0" // 1 unknown,2 normal,3 low,4 depleted
	OIDUpsMinutesRemain  = "1.3.6.1.2.1.33.1.2.3.0"
	OIDUpsChargeRemain   = "1.3.6.1.2.1.33.1.2.4.0" // %
	OIDUpsOutputSource   = "1.3.6.1.2.1.33.1.4.1.0" // 3 normal(mains),5 battery
	OIDUpsOutputLoadWalk = "1.3.6.1.2.1.33.1.4.4.1.5"

	// Printer-MIB (RFC 1759)
	OIDPrtSuppliesDescr = "1.3.6.1.2.1.43.11.1.1.6"
	OIDPrtSuppliesLevel = "1.3.6.1.2.1.43.11.1.1.9"
	OIDPrtSuppliesMax   = "1.3.6.1.2.1.43.11.1.1.8"
)

// Session — открытое SNMP-соединение.
type Session struct{ c *g.GoSNMP }

// Dial открывает SNMPv2c-сессию (UDP). community — community-строка («public» и т.п.).
func Dial(target string, port uint16, community string, timeout time.Duration) (*Session, error) {
	if port == 0 {
		port = 161
	}
	if community == "" {
		community = "public"
	}
	c := &g.GoSNMP{
		Target:    target,
		Port:      port,
		Community: community,
		Version:   g.Version2c,
		Timeout:   timeout,
		Retries:   1,
		MaxOids:   60,
	}
	if err := c.Connect(); err != nil {
		return nil, err
	}
	return &Session{c: c}, nil
}

// Close закрывает соединение.
func (s *Session) Close() {
	if s.c != nil && s.c.Conn != nil {
		_ = s.c.Conn.Close()
	}
}

// Get запрашивает набор OID и возвращает их по имени (без ведущей точки).
func (s *Session) Get(oids []string) (map[string]g.SnmpPDU, error) {
	res, err := s.c.Get(oids)
	if err != nil {
		return nil, err
	}
	m := make(map[string]g.SnmpPDU, len(res.Variables))
	for _, v := range res.Variables {
		m[strings.TrimPrefix(v.Name, ".")] = v
	}
	return m, nil
}

// Walk обходит поддерево OID и возвращает все листья.
func (s *Session) Walk(root string) ([]g.SnmpPDU, error) {
	return s.c.WalkAll(root)
}

// ── Конвертеры значений PDU (чистые, тестируемые) ───────────────────────────

// Str извлекает строковое значение PDU (OCTET STRING).
func Str(p g.SnmpPDU) string {
	switch v := p.Value.(type) {
	case []byte:
		return strings.TrimSpace(string(v))
	case string:
		return strings.TrimSpace(v)
	}
	return ""
}

// Int извлекает целочисленное значение PDU (INTEGER/Gauge/Counter/TimeTicks).
func Int(p g.SnmpPDU) int64 {
	if p.Value == nil {
		return 0
	}
	if bi := g.ToBigInt(p.Value); bi != nil {
		return bi.Int64()
	}
	return 0
}

// Usable сообщает, что PDU содержит реальное значение (не NoSuchObject/NoSuchInstance/EndOfMib).
func Usable(p g.SnmpPDU) bool {
	switch p.Type {
	case g.NoSuchObject, g.NoSuchInstance, g.EndOfMibView, g.Null:
		return false
	}
	return p.Value != nil
}

// ── Интерпретация (чистые функции) ──────────────────────────────────────────

// IndexOf возвращает суффикс-индекс PDU относительно базового OID
// (например, для ".1.3.6.1.2.1.2.2.1.2.7" и базы "1.3.6.1.2.1.2.2.1.2" → "7").
func IndexOf(pduName, base string) string {
	n := strings.TrimPrefix(pduName, ".")
	if strings.HasPrefix(n, base+".") {
		return n[len(base)+1:]
	}
	return ""
}

// IndexMap строит карту «суффикс-индекс → целое значение» из результатов Walk.
func IndexMap(vars []g.SnmpPDU, base string) map[string]int64 {
	m := make(map[string]int64, len(vars))
	for _, v := range vars {
		if idx := IndexOf(v.Name, base); idx != "" {
			m[idx] = Int(v)
		}
	}
	return m
}

// SummarizePorts по статусам ifOperStatus считает up/down/total
// (1=up; notPresent=6 не учитывается в total).
func SummarizePorts(statuses []int64) (up, down, total int) {
	for _, s := range statuses {
		if s == 6 { // notPresent
			continue
		}
		total++
		if s == 1 {
			up++
		} else {
			down++
		}
	}
	return
}

// BatteryStatusText переводит upsBatteryStatus в текст.
func BatteryStatusText(v int64) string {
	switch v {
	case 2:
		return "норма"
	case 3:
		return "низкий заряд"
	case 4:
		return "разряжена"
	default:
		return "неизвестно"
	}
}

// OnBattery определяет работу от батареи по upsOutputSource (5=battery).
func OnBattery(outputSource int64) bool { return outputSource == 5 }

// SupplyPct рассчитывает процент расходника принтера (level/max*100).
// Спец-значения уровня: -1 (other), -2 (unknown), -3 (есть, точно не известно).
func SupplyPct(level, max int64) (pct int, known bool) {
	if level < 0 || max <= 0 {
		return 0, false
	}
	p := int(level * 100 / max)
	if p > 100 {
		p = 100
	}
	return p, true
}
