//go:build windows

package main

import (
	"encoding/base64"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Шифрование персонального токена через Windows DPAPI (CryptProtectData):
// данные расшифровываются только под той же учётной записью, что и зашифровала.
var (
	crypt32       = windows.NewLazySystemDLL("crypt32.dll")
	kernel32      = windows.NewLazySystemDLL("kernel32.dll")
	procProtect   = crypt32.NewProc("CryptProtectData")
	procUnprotect = crypt32.NewProc("CryptUnprotectData")
	procLocalFree = kernel32.NewProc("LocalFree")
)

const dpapiPrefix = "dpapi:"

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) dataBlob {
	if len(d) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(d)), pbData: &d[0]}
}

func (b *dataBlob) bytes() []byte {
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

func dpapi(proc *windows.LazyProc, data []byte) ([]byte, bool) {
	in := newBlob(data)
	var out dataBlob
	r, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, false
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return out.bytes(), true
}

// protectString шифрует строку (DPAPI) и кодирует в base64 с префиксом.
func protectString(s string) string {
	if s == "" {
		return ""
	}
	enc, ok := dpapi(procProtect, []byte(s))
	if !ok {
		return s // не удалось — храним как есть, чтобы не потерять токен
	}
	return dpapiPrefix + base64.StdEncoding.EncodeToString(enc)
}

// unprotectString расшифровывает строку; легаси/нешифрованное значение
// (без префикса) возвращается как есть.
func unprotectString(s string) string {
	if !strings.HasPrefix(s, dpapiPrefix) {
		return s
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, dpapiPrefix))
	if err != nil {
		return ""
	}
	dec, ok := dpapi(procUnprotect, raw)
	if !ok {
		return ""
	}
	return string(dec)
}
