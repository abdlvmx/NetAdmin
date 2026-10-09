package edition

import (
	"debug/buildinfo"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"unicode"
)

// ReadBinary reads edition metadata without executing the candidate. Missing or
// unreadable Go metadata is an error; it must never imply the standard edition.
func ReadBinary(path string) (string, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("не удалось прочитать сведения Go о сборке: %w", err)
	}
	return ParseBuildInfo(info)
}

// ParseBuildInfo derives the edition from the compiler-recorded build tags.
// Old standard Go builds without -tags remain recognizable as standard.
func ParseBuildInfo(info *debug.BuildInfo) (string, error) {
	if info == nil || !strings.HasPrefix(info.GoVersion, "go") {
		return "", errors.New("в сборке отсутствуют корректные сведения Go")
	}
	tags, found := "", false
	for _, setting := range info.Settings {
		if setting.Key != "-tags" {
			continue
		}
		if found {
			return "", errors.New("в сборке неоднозначно указаны теги Go")
		}
		tags, found = setting.Value, true
	}
	for _, tag := range strings.FieldsFunc(tags, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		if tag == "securityevents" {
			return "events", nil
		}
	}
	return "standard", nil
}
