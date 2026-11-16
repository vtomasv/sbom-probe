//go:build linux || darwin

package main

import (
	"os"
	"syscall"
)

func acquireRunLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, err
	}
	// Closing releases the kernel lock, including after process termination.
	return file, nil
}
