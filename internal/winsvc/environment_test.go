package winsvc

import "testing"

func TestServiceEnvironmentValue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		want   string
		found  bool
	}{
		{"unset", nil, "", false},
		{"case insensitive", []string{`netadmin_data_dir=C:\Shared Data`}, `C:\Shared Data`, true},
		{"empty override", []string{"NETADMIN_DATA_DIR="}, "", true},
		{"last override", []string{"NETADMIN_DATA_DIR=old", "NETADMIN_DATA_DIR=new"}, "new", true},
		{"equals inside value", []string{`NETADMIN_DATA_DIR=C:\name=part`}, `C:\name=part`, true},
		{"unrelated and malformed", []string{"OTHER=something", "NETADMIN_DATA_DIR", "=C:\\bad"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, found := serviceEnvironmentValue(tc.values, "NETADMIN_DATA_DIR")
			if value != tc.want || found != tc.found {
				t.Fatalf("value=%q found=%v, want %q %v", value, found, tc.want, tc.found)
			}
		})
	}
}
