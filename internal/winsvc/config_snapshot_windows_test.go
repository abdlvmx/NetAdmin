//go:build windows

package winsvc

import (
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestServiceConfigSnapshotRetainsCustomCommandAndStartup(t *testing.T) {
	old := mgr.Config{
		ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: mgr.StartManual,
		ErrorControl: mgr.ErrorSevere, BinaryPathName: `"D:\Custom Apps\agent.exe" -custom-argument`,
		LoadOrderGroup: "custom-group", Dependencies: []string{"Tcpip", "Dnscache"},
		DisplayName: "Custom service", Description: "Previous description", SidType: 1,
		DelayedAutoStart: true, ServiceStartName: `DOMAIN\custom-account`, Password: "never-rewrite",
	}
	got := configSnapshotValue(old)
	want := old
	want.ServiceStartName, want.Password = "", ""
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rollback discarded command arguments or startup metadata: got %+v want %+v", got, want)
	}
	old.Dependencies[0] = "mutated later"
	if got.Dependencies[0] != "Tcpip" {
		t.Fatal("captured configuration depends on later mutations")
	}
}
