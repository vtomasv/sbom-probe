package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const maxSBOMBytes = 60 * 1024 * 1024

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.Len()
	if len(p) > remaining {
		_, _ = b.Buffer.Write(p[:remaining])
		return remaining, errors.New("salida de Syft supera el límite")
	}
	return b.Buffer.Write(p)
}

func scan(ctx context.Context, cfg settings) (json.RawMessage, error) {
	if cfg.InventoryMode == "native" {
		return nativeInventory(ctx, cfg.ScanPath)
	}
	info, err := os.Stat(cfg.ScanPath)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("scan_path debe ser un directorio existente: %s", cfg.ScanPath)
	}
	work, err := os.MkdirTemp(cfg.StateDir, ".syft-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	syftConfig := filepath.Join(work, "syft.yaml")
	if err := os.WriteFile(syftConfig, []byte("check-for-app-update: false\nenrich: []\n"), 0600); err != nil {
		return nil, err
	}
	args := []string{"--config", syftConfig, "scan", "dir:" + cfg.ScanPath, "--output", "cyclonedx-json", "--select-catalogers", "installed"}
	for _, exclude := range scanExclusions(cfg) {
		args = append(args, "--exclude", exclude)
	}
	command := exec.CommandContext(ctx, cfg.SyftPath, args...)
	command.Env = cleanSyftEnvironment()
	command.Dir = work
	command.WaitDelay = 5 * time.Second
	output := &boundedBuffer{limit: maxSBOMBytes}
	stderr := &boundedBuffer{limit: 64 * 1024}
	command.Stdout = output
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("escaneo cancelado o agotó scan_timeout: %w", ctx.Err())
		}
		return nil, fmt.Errorf("Syft no pudo generar SBOM: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	result := json.RawMessage(bytes.TrimSpace(output.Bytes()))
	if err := validateSBOM(result); err != nil {
		return nil, err
	}
	return result, nil
}

func validateSBOM(data json.RawMessage) error {
	var document struct {
		Format      string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(data, &document); err != nil || document.Format != "CycloneDX" || document.SpecVersion == "" {
		return errors.New("Syft debe generar un documento CycloneDX JSON válido")
	}
	return nil
}

func scanExclusions(cfg settings) []string {
	excludes := []string{"./proc/**", "./sys/**", "./dev/**", "./run/**"}
	excludes = append(excludes, cfg.ScanExcludes...)
	paths := []string{cfg.StateDir, cfg.ConfigPath, cfg.TokenFile, cfg.CAFile, cfg.ClientCertFile, cfg.ClientKeyFile}
	for _, path := range paths {
		if path == "" {
			continue
		}
		relative, err := filepath.Rel(cfg.ScanPath, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		pattern := "./" + filepath.ToSlash(relative)
		excludes = append(excludes, pattern)
		if path == cfg.StateDir {
			excludes = append(excludes, pattern+"/**")
		}
	}
	return excludes
}

func cleanSyftEnvironment() []string {
	result := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(entry), "SYFT_") {
			result = append(result, entry)
		}
	}
	return append(result, "SYFT_CHECK_FOR_APP_UPDATE=false")
}

var _ io.Writer = (*boundedBuffer)(nil)
