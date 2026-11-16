package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"
)

type report struct {
	SchemaVersion int             `json:"schema_version"`
	ReportID      string          `json:"report_id"`
	MachineID     string          `json:"machine_id"`
	ClientID      string          `json:"client_id"`
	CollectedAt   time.Time       `json:"collected_at"`
	Hostname      string          `json:"hostname"`
	OS            string          `json:"os"`
	Arch          string          `json:"arch"`
	Source        string          `json:"source"`
	Metadata      metadata        `json:"metadata"`
	SBOM          json.RawMessage `json:"sbom"`
}

func newClient(cfg settings) (*http.Client, string, error) {
	tokenBytes, err := readFileLimited(cfg.TokenFile, 16*1024)
	if err != nil {
		return nil, "", fmt.Errorf("leer token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if len(token) < 24 || len(token) > 512 || strings.IndexFunc(token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil, "", errors.New("token_file debe contener un token de 24 a 512 bytes sin espacios ni caracteres de control")
	}
	certBytes, err := readFileLimited(cfg.CAFile, 1024*1024)
	if err != nil {
		return nil, "", fmt.Errorf("leer CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certBytes) {
		return nil, "", errors.New("ca_file debe contener certificados PEM válidos")
	}
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if cfg.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, "", fmt.Errorf("cargar certificado mTLS: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig,
		ResponseHeaderTimeout: cfg.RequestLimit, IdleConnTimeout: 30 * time.Second,
	}
	client := &http.Client{
		Transport: transport, Timeout: cfg.RequestLimit,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("el servidor no debe redirigir reportes")
		},
	}
	return client, token, nil
}

func collectAndSend(ctx context.Context, cfg settings, machineID string, client *http.Client, token string) error {
	lock, err := acquireRunLock(filepath.Join(cfg.StateDir, "run.lock"))
	if err != nil {
		return fmt.Errorf("otra ejecución está activa: %w", err)
	}
	defer lock.Close()
	outbox := filepath.Join(cfg.StateDir, "pending-report.json")
	data, err := readFileLimited(outbox, 64*1024*1024)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		var pending report
		if err := json.Unmarshal(data, &pending); err != nil || pending.ClientID != cfg.ClientID ||
			pending.MachineID != machineID || !uuidV4.MatchString(pending.ReportID) {
			return errors.New("reporte pendiente inválido o pertenece a otra identidad o cliente, revise pending-report.json")
		}
		if err := upload(ctx, client, cfg.Endpoint, token, data); err != nil {
			return err
		}
		if err := os.Remove(outbox); err != nil {
			return err
		}
		log.Printf("reporte pendiente entregado, máquina=%s", machineID)
		return nil
	}
	scanCtx, cancel := context.WithTimeout(ctx, cfg.ScanLimit)
	sbom, err := scan(scanCtx, cfg)
	cancel()
	if err != nil {
		return err
	}
	reportID, err := newID()
	if err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return errors.New("no se pudo determinar hostname")
	}
	payload := report{
		SchemaVersion: 1, ReportID: reportID, MachineID: machineID, ClientID: cfg.ClientID,
		CollectedAt: time.Now().UTC(), Hostname: hostname, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Source: cfg.ScanPath, Metadata: cfg.Metadata, SBOM: sbom,
	}
	data, err = json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(data) > 64*1024*1024 {
		return errors.New("el reporte supera 64 MiB")
	}
	if err := writeAtomic(outbox, data); err != nil {
		return err
	}
	if err := upload(ctx, client, cfg.Endpoint, token, data); err != nil {
		return err
	}
	if err := os.Remove(outbox); err != nil {
		return err
	}
	log.Printf("reporte entregado, cliente=%s máquina=%s reporte=%s", cfg.ClientID, machineID, reportID)
	return nil
}

func writeAtomic(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func upload(ctx context.Context, client *http.Client, endpoint, token string, data []byte) error {
	var lastError error
	for attempt := 0; attempt < 3; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusCreated {
				return nil
			}
			lastError = fmt.Errorf("el servidor respondió HTTP %d", response.StatusCode)
			if response.StatusCode != http.StatusTooManyRequests && response.StatusCode < 500 {
				return lastError
			}
		} else {
			lastError = fmt.Errorf("enviar reporte: %w", err)
		}
		if attempt == 2 {
			break
		}
		timer := time.NewTimer(time.Duration(1<<attempt) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("%w, reporte conservado para el próximo ciclo", lastError)
}
