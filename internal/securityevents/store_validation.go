//go:build securityevents

package securityevents

import (
	"encoding/json"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func validHexID(value string) bool {
	return len(value) == 32 && strings.Trim(value, "0123456789abcdef") == ""
}

func boundedText(value string, limit int, whitespace bool) bool {
	return len(value) <= limit && utf8.ValidString(value) && strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) && !(whitespace && (r == '\t' || r == '\r' || r == '\n'))
	}) < 0
}

func profileChannel(profile, channel string) bool {
	return channel == "System" && (profile == "system" || profile == "security") || channel == "Security" && profile == "security"
}

func validEventTime(stamp, now time.Time) bool {
	_, offset := stamp.Zone()
	return !stamp.IsZero() && offset == 0 && stamp.Year() >= 1601 && stamp.Year() <= 9999 && !stamp.After(now.Add(5*time.Minute))
}

// Keep provider/ID pairs and field names identical to eventlog/parser.go.
// EqualFold mirrors the reader's provider-name comparison, without permitting
// substring matches or collecting any additional provider/ID combination.
func eventFields(event Event) (map[string]bool, bool) {
	names := []string{}
	provider := ""
	switch event.Channel {
	case "System":
		switch event.EventID {
		case 7045:
			provider = "Service Control Manager"
			names = []string{"ServiceName", "ServiceType", "StartType"}
		case 6005, 6006, 6008:
			provider = "EventLog"
		case 104:
			provider = "Microsoft-Windows-Eventlog"
			names = []string{"Channel"}
		}
	case "Security":
		switch event.EventID {
		case 4625:
			provider = "Microsoft-Windows-Security-Auditing"
			names = []string{"TargetUserName", "TargetDomainName", "IpAddress", "LogonType", "Status", "SubStatus", "FailureReason"}
		case 1102:
			provider = "Microsoft-Windows-Eventlog"
		}
	}
	if provider == "" || !strings.EqualFold(provider, event.Provider) {
		return nil, false
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	return allowed, true
}

func validateEvent(event Event, now time.Time) error {
	if !validHexID(event.StreamID) || event.RecordID == 0 || event.Version < 0 || event.Version > 255 || !validEventTime(event.TimeUTC, now) {
		return ErrInvalid
	}
	allowed, ok := eventFields(event)
	if !ok || len(event.Fields) > len(allowed) {
		return ErrInvalid
	}
	for name, value := range event.Fields {
		if !allowed[name] || !boundedText(value, 256, true) || strings.ContainsAny(value, "\r\n") {
			return ErrInvalid
		}
	}
	encoded, err := json.Marshal(event)
	if err != nil || len(encoded) > 4096 {
		return ErrInvalid
	}
	return nil
}

func validateChannels(channels []ChannelStatus) error {
	if len(channels) > 2 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, channel := range channels {
		if !profileChannel("security", channel.Channel) || seen[channel.Channel] || !boundedText(channel.Error, 256, true) {
			return ErrInvalid
		}
		switch channel.State {
		case "ready", "error", "disabled", "paused", "collecting":
		default:
			return ErrInvalid
		}
		seen[channel.Channel] = true
	}
	return nil
}

func validateStatus(status Status, now time.Time) error {
	if status.Generation != "" && !validHexID(status.Generation) || !boundedText(status.Error, 512, true) || status.QueueBytes < 0 || status.QueueBytes > MaxQueueBytes || !status.LastCollected.IsZero() && !validEventTime(status.LastCollected, now) {
		return ErrInvalid
	}
	switch status.State {
	case "", "disabled", "pending", "collecting", "paused", "error":
	default:
		return ErrInvalid
	}
	if err := validateChannels(status.Channels); err != nil {
		return err
	}
	encoded, err := json.Marshal(status)
	if err != nil || len(encoded) > 4096 {
		return ErrInvalid
	}
	return nil
}

func validateBatch(batch Batch, now time.Time) ([]byte, error) {
	if !validHexID(batch.ID) || !validHexID(batch.Generation) || len(batch.Events) > MaxBatchEvents || len(batch.Gaps) > 2 || validateChannels(batch.Health) != nil {
		return nil, ErrInvalid
	}
	for _, event := range batch.Events {
		if err := validateEvent(event, now); err != nil {
			return nil, err
		}
	}
	seen := map[string]bool{}
	for _, gap := range batch.Gaps {
		if !profileChannel("security", gap.Channel) || seen[gap.Channel] {
			return nil, ErrInvalid
		}
		switch gap.Reason {
		case "invalid_cursor", "invalid_bookmark", "bookmark_unavailable", "bookmark_reused", "channel_changed", "record_order_changed":
		default:
			return nil, ErrInvalid
		}
		seen[gap.Channel] = true
	}
	payload, err := json.Marshal(batch)
	if err != nil || len(payload) > MaxBatchBytes {
		return nil, ErrInvalid
	}
	return payload, nil
}
