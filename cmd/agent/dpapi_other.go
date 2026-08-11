//go:build !windows

package main

// На не-Windows DPAPI недоступен — храним как есть (заглушка).
func protectString(s string) string   { return s }
func unprotectString(s string) string { return s }
