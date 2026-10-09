//go:build securityevents

package eventlog

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func eventXML(channel, provider string, id int, data string) string {
	return fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="%s"/><EventID>%d</EventID><Version>0</Version><TimeCreated SystemTime="2026-10-08T11:12:13.1234567Z"/><EventRecordID>123</EventRecordID><Channel>%s</Channel><Computer>PRIVATE-PC</Computer></System>%s</Event>`, provider, id, channel, data)
}

func TestParserTransmitsOnlySelectedFields(t *testing.T) {
	data := `<EventData><Data Name="TargetUserName">worker</Data><Data Name="TargetDomainName">OFFICE</Data><Data Name="IpAddress">192.0.2.3</Data><Data Name="LogonType">3</Data><Data Name="Status">0xc000006d</Data><Data Name="SubStatus">0xc000006a</Data><Data Name="FailureReason">%%2304</Data><Data Name="ProcessName">PRIVATE-PROCESS</Data><Data Name="CommandLine">SECRET-COMMAND</Data><Data Name="Password">SECRET-PASSWORD</Data><Data Name="SubjectUserName">PRIVATE-SUBJECT</Data></EventData><RenderingInfo><Message>PRIVATE-RAW-MESSAGE</Message></RenderingInfo>`
	fp, event, err := parseEvent(eventXML("Security", "Microsoft-Windows-Security-Auditing", 4625, data), "Security", strings.Repeat("a", 32))
	if err != nil || event == nil {
		t.Fatalf("parse selected event: %v", err)
	}
	if fp.RecordID != 123 || len(event.Fields) != 7 || event.Fields["IpAddress"] != "192.0.2.3" {
		t.Fatalf("unexpected normalized event: %+v", event)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PRIVATE", "SECRET", "CommandLine", "ProcessName", "Password", "RenderingInfo"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("unselected information leaked: %q", secret)
		}
	}
	if event.TimeUTC.Location() != time.UTC || event.TimeUTC.Nanosecond() != 123456700 {
		t.Fatalf("timestamp lost precision or UTC: %v", event.TimeUTC)
	}
}

func TestParserServiceAndClearedEvents(t *testing.T) {
	_, service, err := parseEvent(eventXML("System", "Service Control Manager", 7045, `<EventData><Data Name="ServiceName">Printer</Data><Data Name="ServiceType">user mode service</Data><Data Name="StartType">auto start</Data><Data Name="ImagePath">PRIVATE-EXECUTABLE</Data><Data Name="AccountName">PRIVATE-ACCOUNT</Data></EventData>`), "System", strings.Repeat("a", 32))
	if err != nil || service == nil || len(service.Fields) != 3 || service.Fields["ServiceName"] != "Printer" {
		t.Fatalf("service event: %+v %v", service, err)
	}
	_, cleared, err := parseEvent(eventXML("System", "Microsoft-Windows-Eventlog", 104, `<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>PRIVATE-USER</SubjectUserName><Channel>Application</Channel><BackupPath>PRIVATE-BACKUP</BackupPath></LogFileCleared></UserData>`), "System", strings.Repeat("a", 32))
	if err != nil || cleared == nil || len(cleared.Fields) != 1 || cleared.Fields["Channel"] != "Application" {
		t.Fatalf("cleared event: %+v %v", cleared, err)
	}
	_, audit, err := parseEvent(eventXML("Security", "Microsoft-Windows-Eventlog", 1102, `<UserData><LogFileCleared><SubjectUserName>PRIVATE-USER</SubjectUserName></LogFileCleared></UserData>`), "Security", strings.Repeat("a", 32))
	if err != nil || audit == nil || len(audit.Fields) != 0 {
		t.Fatalf("audit cleared event/provider: %+v %v", audit, err)
	}
}

func TestParserBoundsUnicodeFieldsAndOutput(t *testing.T) {
	var data strings.Builder
	data.WriteString("<EventData>")
	for _, key := range []string{"TargetUserName", "TargetDomainName", "IpAddress", "LogonType", "Status", "SubStatus", "FailureReason"} {
		fmt.Fprintf(&data, `<Data Name="%s">%s&#10;end</Data>`, key, strings.Repeat("界🙂", 600))
	}
	data.WriteString("</EventData>")
	_, event, err := parseEvent(eventXML("Security", "Microsoft-Windows-Security-Auditing", 4625, data.String()), "Security", strings.Repeat("a", 32))
	if err != nil || event == nil {
		t.Fatalf("bounded parse: %v", err)
	}
	for name, value := range event.Fields {
		if len(value) > maxFieldBytes || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
			t.Fatalf("unsafe field %s: %q", name, value)
		}
	}
	encoded, _ := json.Marshal(event)
	if len(encoded) > maxEventBytes {
		t.Fatalf("event exceeds bound: %d", len(encoded))
	}
}

func TestParserBoundsJSONEscapingWithoutRejectingRecord(t *testing.T) {
	var data strings.Builder
	data.WriteString("<EventData>")
	for _, key := range []string{"TargetUserName", "TargetDomainName", "IpAddress", "LogonType", "Status", "SubStatus", "FailureReason"} {
		fmt.Fprintf(&data, `<Data Name="%s">%s</Data>`, key, strings.Repeat("&lt;&amp;&gt;", 100))
	}
	data.WriteString("</EventData>")
	_, event, err := parseEvent(eventXML("Security", "Microsoft-Windows-Security-Auditing", 4625, data.String()), "Security", strings.Repeat("a", 32))
	if err != nil || event == nil {
		t.Fatalf("escaped legitimate record rejected: %v", err)
	}
	encoded, _ := json.Marshal(event)
	if len(encoded) > maxEventBytes {
		t.Fatalf("escaped record exceeds wire bound: %d", len(encoded))
	}
}

func TestParserSkipsUnselectedButPreservesFingerprint(t *testing.T) {
	for _, raw := range []string{
		eventXML("System", "Unrelated Provider", 7045, ""),
		eventXML("System", "EventLog", 1234, ""),
		eventXML("Security", "Microsoft-Windows-Security-Auditing", 4624, ""),
	} {
		channel := "System"
		if strings.Contains(raw, "<Channel>Security") {
			channel = "Security"
		}
		fp, event, err := parseEvent(raw, channel, strings.Repeat("a", 32))
		if err != nil || event != nil || fp.RecordID != 123 || fp.Time == "" {
			t.Fatalf("unselected event cannot advance: %+v %v", fp, err)
		}
	}
}

func TestParserRejectsMalformedMetadataAndOversize(t *testing.T) {
	good := eventXML("System", "EventLog", 6005, "")
	bad := []string{
		strings.Replace(good, "2026-10-08T11:12:13.1234567Z", "not-a-time", 1),
		strings.Replace(good, "<EventID>6005", "<EventID>0", 1),
		strings.Replace(good, "<EventRecordID>123", "<EventRecordID>0", 1),
		strings.Replace(good, `<Provider Name="EventLog"`, `<Provider Name=""`, 1),
		strings.Replace(good, "<Channel>System", "<Channel>Security", 1),
		strings.Replace(good, "<Version>0", "<Version>999", 1),
		good + strings.Repeat("x", maxXMLBytes),
		"<Event><System>",
	}
	for i, raw := range bad {
		if _, _, err := parseEvent(raw, "System", strings.Repeat("a", 32)); err == nil {
			t.Fatalf("malformed event %d accepted", i)
		}
	}
}

func TestCursorRoundTripAndRejectsChangedScope(t *testing.T) {
	fp := fingerprint{RecordID: 123, Time: "2026-10-08T11:12:13Z", Provider: "EventLog", EventID: 6005}
	stream, err := newStreamID()
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := encodeCursor("System", stream, `<BookmarkList><Bookmark Channel="System" RecordId="123" IsCurrent="true"/></BookmarkList>`, fp, false)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := decodeCursor("System", cursor)
	if err != nil || saved.Fingerprint != fp || saved.Empty {
		t.Fatalf("round trip: %+v %v", saved, err)
	}
	if _, err := decodeCursor("Security", cursor); err == nil {
		t.Fatal("cursor crossed channels")
	}
	changed := cursor
	changed.StreamID = "not-a-stream"
	if _, err := decodeCursor("System", changed); err == nil {
		t.Fatal("invalid stream accepted")
	}
	changed = cursor
	changed.Bookmark += `{}`
	if _, err := decodeCursor("System", changed); err == nil {
		t.Fatal("trailing cursor data accepted")
	}
	empty, err := encodeCursor("System", stream, "", fingerprint{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if saved, err := decodeCursor("System", empty); err != nil || !saved.Empty {
		t.Fatalf("empty tail round trip: %+v %v", saved, err)
	}
}

func TestChannelsAreAllowlistedAndIndependent(t *testing.T) {
	if len(Channels("unknown")) != 0 || len(Channels("system")) != 1 || len(Channels("security")) != 2 {
		t.Fatal("unexpected profiles")
	}
	channels := Channels("security")
	channels[0] = "Application"
	if Channels("security")[0] != "System" {
		t.Fatal("caller changed shared channel allowlist")
	}
}
