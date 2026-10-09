//go:build securityevents && windows

package eventlog

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wevtapi            = windows.NewLazySystemDLL("wevtapi.dll")
	procQuery          = wevtapi.NewProc("EvtQuery")
	procNext           = wevtapi.NewProc("EvtNext")
	procSeek           = wevtapi.NewProc("EvtSeek")
	procRender         = wevtapi.NewProc("EvtRender")
	procCreateBookmark = wevtapi.NewProc("EvtCreateBookmark")
	procUpdateBookmark = wevtapi.NewProc("EvtUpdateBookmark")
	procClose          = wevtapi.NewProc("EvtClose")
)

const (
	queryChannel   = 1
	queryForward   = 0x100
	queryReverse   = 0x200
	seekBookmark   = 4
	seekStrict     = 0x10000
	renderXML      = 1
	renderBookmark = 2
)

func closeEvent(handle uintptr) {
	if handle != 0 {
		procClose.Call(handle)
	}
}

func nativeError(operation string, err error) error {
	if err == nil || err == syscall.Errno(0) {
		err = windows.ERROR_GEN_FAILURE
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func query(channel string, reverse bool) (uintptr, error) {
	path, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	flags := uintptr(queryChannel | queryForward)
	if reverse {
		flags = queryChannel | queryReverse
	}
	handle, _, callErr := procQuery.Call(0, uintptr(unsafe.Pointer(path)), 0, flags)
	runtime.KeepAlive(path)
	if handle == 0 {
		return 0, nativeError("EvtQuery", callErr)
	}
	return handle, nil
}

func next(ctx context.Context, handle uintptr) (uintptr, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var event uintptr
	var returned uint32
	ok, _, err := procNext.Call(handle, 1, uintptr(unsafe.Pointer(&event)), 100, 0, uintptr(unsafe.Pointer(&returned)))
	if ok == 0 {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, nativeError("EvtNext", err)
	}
	if returned != 1 || event == 0 {
		closeEvent(event)
		return 0, errors.New("EvtNext returned no event")
	}
	if err := ctx.Err(); err != nil {
		closeEvent(event)
		return 0, err
	}
	return event, nil
}

func render(handle uintptr, flags uintptr) (string, error) {
	var used, properties uint32
	ok, _, err := procRender.Call(0, handle, flags, 0, 0, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if ok == 0 && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return "", nativeError("EvtRender", err)
	}
	if used == 0 || used > maxXMLBytes || used%2 != 0 {
		return "", errors.New("rendered event exceeds XML size limit")
	}
	buffer := make([]uint16, used/2)
	ok, _, err = procRender.Call(0, handle, flags, uintptr(used), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if ok == 0 {
		return "", nativeError("EvtRender", err)
	}
	runtime.KeepAlive(buffer)
	if int(used) > len(buffer)*2 {
		return "", errors.New("invalid rendered event size")
	}
	return windows.UTF16ToString(buffer), nil
}

func createBookmark(raw string) (uintptr, error) {
	var pointer *uint16
	var err error
	if raw != "" {
		pointer, err = windows.UTF16PtrFromString(raw)
		if err != nil {
			return 0, err
		}
	}
	handle, _, callErr := procCreateBookmark.Call(uintptr(unsafe.Pointer(pointer)))
	runtime.KeepAlive(pointer)
	if handle == 0 {
		return 0, nativeError("EvtCreateBookmark", callErr)
	}
	return handle, nil
}

func updateBookmark(bookmark, event uintptr) (string, error) {
	ok, _, err := procUpdateBookmark.Call(bookmark, event)
	if ok == 0 {
		return "", nativeError("EvtUpdateBookmark", err)
	}
	return render(bookmark, renderBookmark)
}

func seek(query, bookmark uintptr) error {
	// LONGLONG is passed as two stack words on 32-bit Windows.
	args := []uintptr{query, 0}
	if unsafe.Sizeof(uintptr(0)) == 4 {
		args = append(args, 0)
	}
	args = append(args, bookmark, 0, seekBookmark|seekStrict)
	ok, _, err := procSeek.Call(args...)
	if ok == 0 {
		return nativeError("EvtSeek", err)
	}
	return nil
}

func missingBookmark(err error) bool {
	return errors.Is(err, windows.ERROR_EVT_QUERY_RESULT_STALE) || errors.Is(err, windows.ERROR_EVT_QUERY_RESULT_INVALID_POSITION) || errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_NO_MORE_ITEMS)
}

func atTail(ctx context.Context, channel, reason string) (ReadResult, error) {
	var result ReadResult
	stream, err := newStreamID()
	if err != nil {
		return result, err
	}
	q, err := query(channel, true)
	if err != nil {
		return result, err
	}
	defer closeEvent(q)
	event, err := next(ctx, q)
	if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
		result.Cursor, err = encodeCursor(channel, stream, "", fingerprint{}, true)
	} else if err == nil {
		defer closeEvent(event)
		raw, renderErr := render(event, renderXML)
		if renderErr != nil {
			return result, renderErr
		}
		fp, _, parseErr := parseEvent(raw, channel, stream)
		if parseErr != nil {
			return result, parseErr
		}
		bookmark, bookmarkErr := createBookmark("")
		if bookmarkErr != nil {
			return result, bookmarkErr
		}
		defer closeEvent(bookmark)
		xml, updateErr := updateBookmark(bookmark, event)
		if updateErr != nil {
			return result, updateErr
		}
		result.Cursor, err = encodeCursor(channel, stream, xml, fp, false)
	}
	if err != nil {
		return ReadResult{}, err
	}
	if reason != "" {
		result.Gap = &Gap{Channel: channel, Reason: reason}
	}
	return result, nil
}

// Read begins at the channel's current tail, never importing historical records.
// Later calls advance at most 1000 records and return at most 100 selected events.
// All query handles stay on their creating OS thread, as EvtQuery requires.
// A missing/reused bookmark resets at the current tail and reports a gap.
func Read(ctx context.Context, channel string, cursor Cursor, limit int) (ReadResult, error) {
	if err := ctx.Err(); err != nil {
		return ReadResult{}, err
	}
	if !validChannel(channel) {
		return ReadResult{}, errors.New("event channel is not allowed")
	}
	if limit < 1 || limit > maxBatch {
		return ReadResult{}, errors.New("event limit must be between 1 and 100")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if cursor.Bookmark == "" && cursor.StreamID == "" {
		return atTail(ctx, channel, "")
	}
	saved, err := decodeCursor(channel, cursor)
	if err != nil {
		return atTail(ctx, channel, "invalid_cursor")
	}
	q, err := query(channel, false)
	if err != nil {
		return ReadResult{}, err
	}
	defer closeEvent(q)
	bookmark, err := createBookmark(saved.XML)
	if err != nil {
		return atTail(ctx, channel, "invalid_bookmark")
	}
	defer closeEvent(bookmark)
	if !saved.Empty {
		if err := seek(q, bookmark); err != nil {
			if missingBookmark(err) {
				return atTail(ctx, channel, "bookmark_unavailable")
			}
			return ReadResult{}, err
		}
		anchor, nextErr := next(ctx, q)
		if nextErr != nil {
			if missingBookmark(nextErr) {
				return atTail(ctx, channel, "bookmark_unavailable")
			}
			return ReadResult{}, nextErr
		}
		raw, renderErr := render(anchor, renderXML)
		closeEvent(anchor)
		if renderErr != nil {
			return ReadResult{}, renderErr
		}
		fp, _, parseErr := parseEvent(raw, channel, cursor.StreamID)
		if parseErr != nil {
			return ReadResult{}, parseErr
		}
		if fp != saved.Fingerprint {
			return atTail(ctx, channel, "bookmark_reused")
		}
	}
	result := ReadResult{Cursor: cursor}
	previousRecord := saved.Fingerprint.RecordID
	for scanned := 0; scanned < maxScan && len(result.Events) < limit; scanned++ {
		event, nextErr := next(ctx, q)
		if errors.Is(nextErr, windows.ERROR_NO_MORE_ITEMS) || errors.Is(nextErr, windows.ERROR_TIMEOUT) {
			return result, nil
		}
		if nextErr != nil {
			if missingBookmark(nextErr) {
				// Discard this partial batch: a channel changed while it was read.
				return atTail(ctx, channel, "channel_changed")
			}
			return ReadResult{}, nextErr
		}
		raw, renderErr := render(event, renderXML)
		if renderErr != nil {
			closeEvent(event)
			return ReadResult{}, renderErr
		}
		fp, selected, parseErr := parseEvent(raw, channel, cursor.StreamID)
		if parseErr != nil {
			closeEvent(event)
			return ReadResult{}, parseErr
		}
		if fp.RecordID <= previousRecord {
			closeEvent(event)
			return atTail(ctx, channel, "record_order_changed")
		}
		xml, updateErr := updateBookmark(bookmark, event)
		closeEvent(event)
		if updateErr != nil {
			return ReadResult{}, updateErr
		}
		result.Cursor, err = encodeCursor(channel, cursor.StreamID, xml, fp, false)
		if err != nil {
			return ReadResult{}, err
		}
		previousRecord = fp.RecordID
		if selected != nil {
			result.Events = append(result.Events, *selected)
		}
	}
	return result, nil
}
