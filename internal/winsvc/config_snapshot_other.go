//go:build !windows

package winsvc

func CaptureConfig(string) (func() error, error) { return nil, ErrUnsupported }
