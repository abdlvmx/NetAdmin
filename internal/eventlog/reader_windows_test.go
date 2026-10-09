//go:build securityevents && windows

package eventlog

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// This integration test reads System only. It creates no events and does not
// change or clear any Windows channel or audit policy.
func TestLiveSystemTailAndReusedCursorReset(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	first, err := Read(ctx, "System", Cursor{}, 10)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_EVT_CHANNEL_NOT_FOUND) {
		t.Skipf("System is unavailable to this test identity: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 0 || first.Gap != nil || !validStreamID(first.Cursor.StreamID) || first.Cursor.Bookmark == "" {
		t.Fatalf("first read imported history or has no cursor: %+v", first)
	}
	next, err := Read(ctx, "System", first.Cursor, 10)
	if err != nil {
		t.Fatal(err)
	}
	if next.Gap != nil || next.Cursor.StreamID != first.Cursor.StreamID {
		t.Fatalf("unchanged log reset unexpectedly: %+v", next)
	}
	saved, err := decodeCursor("System", next.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Empty {
		t.Skip("System is empty; a reused record cannot be simulated")
	}
	// Changing the saved anchor models a clear followed by record-ID reuse,
	// without performing either operation on the host.
	saved.Fingerprint.Time = "2001-01-01T00:00:00Z"
	corrupt, err := encodeCursor("System", next.Cursor.StreamID, saved.XML, saved.Fingerprint, false)
	if err != nil {
		t.Fatal(err)
	}
	reset, err := Read(ctx, "System", corrupt, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(reset.Events) != 0 || reset.Gap == nil || reset.Gap.Reason != "bookmark_reused" || reset.Cursor.StreamID == corrupt.StreamID {
		t.Fatalf("reused bookmark did not reset at tail: %+v", reset)
	}
	// A valid native bookmark pointing beyond the live record range models an
	// unavailable/overwritten anchor. EvtSeekStrict must not silently clamp it.
	saved, err = decodeCursor("System", reset.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	recordAttr := regexp.MustCompile(`RecordId=['"][0-9]+['"]`)
	missingXML := recordAttr.ReplaceAllString(saved.XML, `RecordId="9223372036854775806"`)
	if missingXML == saved.XML {
		t.Fatalf("native bookmark has no RecordId attribute")
	}
	saved.Fingerprint.RecordID = 9223372036854775806
	missing, err := encodeCursor("System", reset.Cursor.StreamID, missingXML, saved.Fingerprint, false)
	if err != nil {
		t.Fatal(err)
	}
	reset, err = Read(ctx, "System", missing, 10)
	if err != nil || reset.Gap == nil || reset.Gap.Reason != "bookmark_unavailable" || reset.Cursor.StreamID == missing.StreamID || len(reset.Events) != 0 {
		t.Fatalf("missing bookmark reset: %+v %v", reset, err)
	}
	invalid := Cursor{StreamID: reset.Cursor.StreamID, Bookmark: "broken bookmark"}
	reset, err = Read(ctx, "System", invalid, 10)
	if err != nil || reset.Gap == nil || reset.Gap.Reason != "invalid_cursor" || len(reset.Events) != 0 {
		t.Fatalf("invalid cursor reset: %+v %v", reset, err)
	}
}

func TestReaderRejectsInputsAndCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Read(ctx, "System", Cursor{}, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read: %v", err)
	}
	for _, channel := range []string{"Application", `System"><Query>`, "", strings.Repeat("x", 1000)} {
		if _, err := Read(context.Background(), channel, Cursor{}, 10); err == nil {
			t.Fatalf("unallowed channel %q accepted", channel)
		}
	}
	for _, limit := range []int{0, -1, 101} {
		if _, err := Read(context.Background(), "System", Cursor{}, limit); err == nil {
			t.Fatalf("unbounded limit %d accepted", limit)
		}
	}
}
