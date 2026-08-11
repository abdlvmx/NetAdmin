// Package tz — отображение времени в московской зоне (UTC+3).
// Хранение в БД остаётся в UTC (datetime('now')); конвертация только на вывод.
package tz

import (
	"fmt"
	"time"
)

// Loc — московская зона (фиксированный UTC+3, без переходов).
var Loc = time.FixedZone("МСК", 3*60*60)

var monthsGen = [...]string{
	"января", "февраля", "марта", "апреля", "мая", "июня",
	"июля", "августа", "сентября", "октября", "ноября", "декабря",
}

func parse(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05Z", "2006-01-02 15:04"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// DateTime: "02.01 15:04" в МСК (или исходная строка, если не распарсилось).
func DateTime(s string) string {
	if t, ok := parse(s); ok {
		return t.In(Loc).Format("02.01 15:04")
	}
	return s
}

// Time: "15:04" в МСК.
func Time(s string) string {
	if t, ok := parse(s); ok {
		return t.In(Loc).Format("15:04")
	}
	return s
}

// Full: "2006-01-02 15:04:05" в МСК (для меток графиков).
func Full(s string) string {
	if t, ok := parse(s); ok {
		return t.In(Loc).Format("2006-01-02 15:04:05")
	}
	return s
}

// TodayRU: текущая дата в МСК, напр. "2 июня 2026".
func TodayRU() string {
	now := time.Now().In(Loc)
	return fmt.Sprintf("%d %s %d", now.Day(), monthsGen[now.Month()-1], now.Year())
}
