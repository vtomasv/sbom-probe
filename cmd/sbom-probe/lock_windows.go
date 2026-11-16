//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

var lockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")

func acquireRunLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var overlapped syscall.Overlapped
	const failImmediately = 0x00000001
	const exclusiveLock = 0x00000002
	result, _, callErr := lockFileEx.Call(file.Fd(), failImmediately|exclusiveLock, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		file.Close()
		return nil, callErr
	}
	// A synchronous file handle is used. Windows releases its locks on close.
	return file, nil
}
