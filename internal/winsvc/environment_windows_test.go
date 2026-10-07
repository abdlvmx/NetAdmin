//go:build windows

package winsvc

import "testing"

func TestServiceEnvironmentExpansionNeverGuessesAdministratorProfile(t *testing.T) {
	for _, value := range []string{`%ProgramData%\NetAdmin`, `%USERPROFILE%\NetAdmin`, `%CUSTOM_DATA_DIR%`, `%UNKNOWN%\data`} {
		if _, err := expandServiceEnvironment(value); err == nil {
			t.Errorf("environment macro was expanded using interactive caller: %q", value)
		}
	}
	for _, value := range []string{"", `C:\ProgramData\NetAdmin`, `D:\Shared Data\NetAdmin`} {
		got, err := expandServiceEnvironment(value)
		if err != nil || got != value {
			t.Errorf("literal service value changed: %q => %q, %v", value, got, err)
		}
	}
}
