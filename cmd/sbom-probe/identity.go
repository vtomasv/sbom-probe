package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const machineIDFile = "machine-id"

var uuidV4 = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)

func newID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	random[6] = random[6]&0x0f | 0x40
	random[8] = random[8]&0x3f | 0x80
	id := hex.EncodeToString(random[:])
	return id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:], nil
}

func getMachineID(stateDir string) (string, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return "", fmt.Errorf("crear directorio de estado: %w", err)
	}
	path := filepath.Join(stateDir, machineIDFile)
	id, err := readMachineID(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return id, err
	}

	id, err = newID()
	if err != nil {
		return "", fmt.Errorf("generar identificador: %w", err)
	}
	temp, err := os.CreateTemp(stateDir, ".machine-id-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()

	if _, err := temp.WriteString(id + "\n"); err != nil {
		return "", err
	}
	if err := temp.Sync(); err != nil {
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}

	// Publish the complete ID without replacing one created by another process.
	if err := os.Link(temp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return readMachineID(path)
		}
		return "", fmt.Errorf("guardar identificador en %s: %w", stateDir, err)
	}
	return id, nil
}

func readMachineID(path string) (string, error) {
	content, err := readFileLimited(path, 64)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(content))
	if !uuidV4.MatchString(id) {
		return "", fmt.Errorf("identificador de máquina inválido en %s", path)
	}
	return id, nil
}
