//go:build windows

package auth

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

func TestMFAKeyNTFSAccessDoesNotInheritPublicPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mfa.key")
	if err := os.WriteFile(path, make([]byte, 32), 0666); err != nil {
		t.Fatal(err)
	}
	if err := protectMFAKey(path); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("key inherited permissions from its parent")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		t.Fatal("missing restrictive key ACL")
	}
	account, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true, account.User.Sid.String(): true}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trusted[sid.String()] {
			t.Fatalf("unexpected key reader: %s", sid.String())
		}
	}
}
