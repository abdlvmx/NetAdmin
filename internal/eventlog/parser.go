//go:build securityevents

package eventlog

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type wireSystem struct {
	Provider struct {
		Name string `xml:"Name,attr"`
	} `xml:"Provider"`
	EventID string `xml:"EventID"`
	Version string `xml:"Version"`
	Time    struct {
		Value string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	RecordID string `xml:"EventRecordID"`
	Channel  string `xml:"Channel"`
}

type wireData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type wireEvent struct {
	XMLName   xml.Name     `xml:"Event"`
	System    []wireSystem `xml:"System"`
	EventData struct {
		Data []wireData `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Cleared []struct {
			Channel string `xml:"Channel"`
		} `xml:"LogFileCleared"`
	} `xml:"UserData"`
}

// parseEvent returns a fingerprint for every well-formed record, including
// unselected ones. Advancing across unselected records prevents rescanning a
// busy channel on every poll. Only selected provider/ID pairs produce Event.
func parseEvent(raw, channel, stream string) (fingerprint, *Event, error) {
	var fp fingerprint
	if len(raw) > maxXMLBytes {
		return fp, nil, errors.New("event XML exceeds size limit")
	}
	var wire wireEvent
	if err := xml.Unmarshal([]byte(raw), &wire); err != nil {
		return fp, nil, fmt.Errorf("invalid event XML: %w", err)
	}
	if len(wire.System) != 1 {
		return fp, nil, errors.New("event must contain one System element")
	}
	system := wire.System[0]
	provider := strings.TrimSpace(system.Provider.Name)
	if provider == "" || len(provider) > maxFieldBytes || strings.IndexFunc(provider, unicode.IsControl) >= 0 || system.Channel != channel {
		return fp, nil, errors.New("invalid event provider or channel")
	}
	id, err := strconv.Atoi(system.EventID)
	if err != nil || id < 1 || id > 65535 {
		return fp, nil, errors.New("invalid event ID")
	}
	version := 0
	if system.Version != "" {
		version, err = strconv.Atoi(system.Version)
		if err != nil || version < 0 || version > 255 {
			return fp, nil, errors.New("invalid event version")
		}
	}
	record, err := strconv.ParseUint(system.RecordID, 10, 64)
	if err != nil || record == 0 {
		return fp, nil, errors.New("invalid event record ID")
	}
	stamp, err := time.Parse(time.RFC3339Nano, system.Time.Value)
	if err != nil || stamp.Year() < 1601 {
		return fp, nil, errors.New("invalid event timestamp")
	}
	stamp = stamp.UTC()
	fp = fingerprint{RecordID: record, Time: stamp.Format(time.RFC3339Nano), Provider: provider, EventID: id, Version: version}
	var names []string
	selected := false
	switch channel {
	case "System":
		switch id {
		case 7045:
			selected = strings.EqualFold(provider, "Service Control Manager")
			names = []string{"ServiceName", "ServiceType", "StartType"}
		case 6005, 6006, 6008:
			selected = strings.EqualFold(provider, "EventLog")
		case 104:
			selected = strings.EqualFold(provider, "Microsoft-Windows-Eventlog")
		}
	case "Security":
		if id == 4625 {
			selected = strings.EqualFold(provider, "Microsoft-Windows-Security-Auditing")
			names = []string{"TargetUserName", "TargetDomainName", "IpAddress", "LogonType", "Status", "SubStatus", "FailureReason"}
		} else if id == 1102 {
			selected = strings.EqualFold(provider, "Microsoft-Windows-Eventlog")
		}
	}
	if !selected {
		return fp, nil, nil
	}
	fields := make(map[string]string)
	for _, name := range names {
		for _, data := range wire.EventData.Data {
			if data.Name == name {
				fields[name] = safeField(data.Value)
				break
			}
		}
	}
	if channel == "System" && id == 104 && len(wire.UserData.Cleared) == 1 {
		fields["Channel"] = safeField(wire.UserData.Cleared[0].Channel)
	}
	event := &Event{StreamID: stream, Channel: channel, Provider: provider, EventID: id, RecordID: record, Version: version, TimeUTC: stamp, Fields: fields}
	encoded, err := json.Marshal(event)
	if err != nil {
		return fp, nil, errors.New("normalized event exceeds size limit")
	}
	// JSON can expand characters such as '<' into six-byte escapes. Keep the
	// complete wire event bounded too, rather than rejecting a legitimate record
	// forever because one selected value contains many escaped characters.
	for len(encoded) > maxEventBytes {
		largestName, largestSize := "", 0
		for name, value := range fields {
			fieldJSON, _ := json.Marshal(value)
			if value != "" && (len(fieldJSON) > largestSize || len(fieldJSON) == largestSize && (largestName == "" || name < largestName)) {
				largestName, largestSize = name, len(fieldJSON)
			}
		}
		if largestName == "" {
			return fp, nil, errors.New("normalized event metadata exceeds size limit")
		}
		runes := []rune(fields[largestName])
		fields[largestName] = string(runes[:len(runes)/2])
		encoded, err = json.Marshal(event)
		if err != nil {
			return fp, nil, err
		}
	}
	return fp, event, nil
}
