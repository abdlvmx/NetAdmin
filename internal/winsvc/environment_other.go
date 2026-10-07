//go:build !windows

package winsvc

func Environment(string, string) (string, error) { return "", ErrUnsupported }
