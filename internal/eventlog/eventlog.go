//go:build securityevents

// Package eventlog reads a deliberately small subset of Windows event fields.
// It never changes audit policy or renders localized event messages.
package eventlog

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxXMLBytes   = 64 << 10
	maxEventBytes = 4 << 10
	maxFieldBytes = 256
	maxScan       = 1000
	maxBatch      = 100
)

type Event struct {
	StreamID string            `json:"stream_id"`
	Channel  string            `json:"channel"`
	Provider string            `json:"provider"`
	EventID  int               `json:"event_id"`
	RecordID uint64            `json:"record_id"`
	Version  int               `json:"version"`
	TimeUTC  time.Time         `json:"time_utc"`
	Fields   map[string]string `json:"fields"`
}

type Gap struct {
	Channel string `json:"channel"`
	Reason  string `json:"reason"`
}

// Bookmark is opaque: it includes native bookmark XML and an event fingerprint.
// Persist it unchanged. A native bookmark alone cannot detect reused record IDs
// after clearing a channel.
type Cursor struct {
	Bookmark string `json:"bookmark"`
	StreamID string `json:"stream_id"`
}

type ReadResult struct {
	Events []Event `json:"events"`
	Cursor Cursor  `json:"cursor"`
	Gap    *Gap    `json:"gap,omitempty"`
}

// Channels returns a fresh allowlist. Unknown profiles collect nothing.
func Channels(profile string) []string {
	switch profile {
	case "system":
		return []string{"System"}
	case "security":
		return []string{"System", "Security"}
	default:
		return nil
	}
}

func validChannel(channel string) bool { return channel == "System" || channel == "Security" }

func newStreamID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func validStreamID(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 16 && len(s) == 32
}

type fingerprint struct {
	RecordID uint64 `json:"record_id"`
	Time     string `json:"time"`
	Provider string `json:"provider"`
	EventID  int    `json:"event_id"`
	Version  int    `json:"version"`
}

type savedBookmark struct {
	Format      int         `json:"format"`
	Channel     string      `json:"channel"`
	XML         string      `json:"xml,omitempty"`
	Fingerprint fingerprint `json:"fingerprint"`
	Empty       bool        `json:"empty,omitempty"`
}

func encodeCursor(channel, stream, nativeXML string, fp fingerprint, empty bool) (Cursor, error) {
	b, err := json.Marshal(savedBookmark{Format: 1, Channel: channel, XML: nativeXML, Fingerprint: fp, Empty: empty})
	if err != nil {
		return Cursor{}, err
	}
	if len(b) > maxXMLBytes {
		return Cursor{}, errors.New("event bookmark exceeds size limit")
	}
	return Cursor{Bookmark: string(b), StreamID: stream}, nil
}

func decodeCursor(channel string, cursor Cursor) (savedBookmark, error) {
	var saved savedBookmark
	if !validStreamID(cursor.StreamID) || len(cursor.Bookmark) == 0 || len(cursor.Bookmark) > maxXMLBytes {
		return saved, errors.New("invalid event cursor")
	}
	dec := json.NewDecoder(strings.NewReader(cursor.Bookmark))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&saved); err != nil {
		return saved, fmt.Errorf("invalid event bookmark: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return saved, errors.New("event bookmark contains trailing data")
	}
	if saved.Format != 1 || saved.Channel != channel || len(saved.XML) > maxXMLBytes {
		return saved, errors.New("event bookmark belongs to another channel or format")
	}
	if saved.Empty {
		if saved.XML != "" || saved.Fingerprint != (fingerprint{}) {
			return saved, errors.New("invalid empty event bookmark")
		}
		return saved, nil
	}
	if saved.XML == "" || saved.Fingerprint.RecordID == 0 || saved.Fingerprint.Provider == "" {
		return saved, errors.New("incomplete event bookmark")
	}
	if _, err := time.Parse(time.RFC3339Nano, saved.Fingerprint.Time); err != nil {
		return saved, errors.New("invalid event bookmark time")
	}
	return saved, nil
}

func safeField(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(value, ""))
	value = strings.TrimSpace(value)
	if len(value) > maxFieldBytes {
		value = value[:maxFieldBytes]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}
