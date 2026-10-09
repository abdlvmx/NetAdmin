package agentbin

import (
	"bytes"
	"debug/buildinfo"

	"netadmin/internal/edition"
)

// EmbeddedEdition reports the actual embedded file, including mismatches.
func EmbeddedEdition() string {
	b, err := fsys.ReadFile(name)
	if err != nil || len(b) == 0 {
		return "unavailable"
	}
	bi, err := buildinfo.Read(bytes.NewReader(b))
	if err != nil {
		return "unknown"
	}
	id, err := edition.ParseBuildInfo(bi)
	if err != nil {
		return "unknown"
	}
	return id
}

func embeddedCompatible() bool { return EmbeddedEdition() == edition.ID }
