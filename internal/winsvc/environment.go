package winsvc

import "strings"

// serviceEnvironmentValue finds an explicit service override, including an
// intentionally empty value. Windows environment names ignore letter case.
func serviceEnvironmentValue(values []string, key string) (string, bool) {
	var result string
	found := false
	for _, entry := range values {
		name, value, ok := strings.Cut(entry, "=")
		if ok && strings.EqualFold(name, key) {
			result, found = value, true
		}
	}
	return result, found
}
