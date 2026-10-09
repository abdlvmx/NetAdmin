//go:build securityevents

// Package securityevents implements the optional observation-only Events module.
package securityevents

import "time"

const (
	Capability     = "security_events_v1"
	MaxBatchEvents = 200
	MaxBatchBytes  = 256 << 10
	MaxQueueBytes  = 32 << 20
	RetentionDays  = 7
)

type Policy struct {
	Enabled    bool   `json:"enabled"`
	Profile    string `json:"profile"`
	Generation string `json:"generation"`
}

type Event struct {
	StreamID string            `json:"stream_id"`
	Channel  string            `json:"channel"`
	Provider string            `json:"provider"`
	EventID  int               `json:"event_id"`
	RecordID uint64            `json:"record_id"`
	Version  int               `json:"version"`
	TimeUTC  time.Time         `json:"time_utc"`
	Fields   map[string]string `json:"fields,omitempty"`
}

type Gap struct {
	Channel string `json:"channel"`
	Reason  string `json:"reason"`
}
type ChannelStatus struct {
	Channel string `json:"channel"`
	State   string `json:"state"`
	Error   string `json:"error,omitempty"`
}
type Batch struct {
	ID         string          `json:"id"`
	Generation string          `json:"generation"`
	Events     []Event         `json:"events"`
	Gaps       []Gap           `json:"gaps,omitempty"`
	Dropped    uint64          `json:"dropped"`
	Health     []ChannelStatus `json:"health,omitempty"`
}
type Status struct {
	Generation    string          `json:"generation"`
	State         string          `json:"state"`
	Error         string          `json:"error,omitempty"`
	LastCollected time.Time       `json:"last_collected"`
	Dropped       uint64          `json:"dropped"`
	QueueBytes    int64           `json:"queue_bytes"`
	Channels      []ChannelStatus `json:"channels,omitempty"`
}
type PollRequest struct {
	Capabilities []string `json:"capabilities"`
	Status       Status   `json:"status"`
}
type PollResponse struct {
	Policy Policy `json:"policy"`
}
