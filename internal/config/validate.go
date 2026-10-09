package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// ValidateFile prevents invalid or unreadable settings from silently starting
// an HTTP listener with defaults. It neither creates nor repairs the file.
func ValidateFile() error {
	f, err := os.Open(ConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(b) > 1<<20 {
		return errors.New("config.json превышает 1 МиБ")
	}
	var object map[string]json.RawMessage
	if err = json.Unmarshal(b, &object); err != nil {
		return fmt.Errorf("config.json: %w", err)
	}
	if object == nil {
		return errors.New("config.json должен содержать объект настроек")
	}
	var cfg Config
	if err = json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("config.json: %w", err)
	}
	return nil
}
