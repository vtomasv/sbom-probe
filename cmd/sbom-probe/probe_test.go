package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIdentityStableAndConcurrent(t *testing.T) {
	dir := t.TempDir()
	results := make(chan string, 20)
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			id, err := getMachineID(dir)
			if err != nil {
				t.Error(err)
				return
			}
			results <- id
		}()
	}
	workers.Wait()
	close(results)
	var expected string
	for id := range results {
		if !uuidV4.MatchString(id) {
			t.Fatalf("bad UUID %q", id)
		}
		if expected == "" {
			expected = id
		}
		if id != expected {
			t.Fatalf("IDs differ %s %s", id, expected)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, machineIDFile), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := getMachineID(dir); err == nil {
		t.Fatal("corrupt identity accepted")
	}
}

func TestConfigValidationAndPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"server_url":"https://localhost:8443/","client_id":"client-a","token_file":"client.token","ca_file":"ca.crt","scan_path":".","syft_path":"syft","interval":"1m","metadata":{"tags":{"team":"ops"}}}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint != "https://localhost:8443/v1/reports" || cfg.ScanPath != dir || cfg.StateDir != filepath.Join(dir, "state") || cfg.ScanInterval != time.Minute {
		t.Fatalf("wrong paths/defaults: %+v", cfg)
	}
	for _, invalid := range []string{
		strings.Replace(content, "https://", "http://", 1),
		strings.Replace(content, "1m", "0s", 1),
		strings.Replace(content, `"client-a"`, `"../client"`, 1),
		strings.Replace(content, `"interval"`, `"unknown"`, 1),
		content + "{}",
	} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readConfig(path); err == nil {
			t.Fatalf("accepted invalid config %s", invalid)
		}
	}
}

func testClient(t *testing.T, server *httptest.Server) (*http.Client, string) {
	t.Helper()
	dir := t.TempDir()
	cert := server.Certificate()
	if cert == nil {
		t.Fatal("server has no cert")
	}
	if _, err := x509.ParseCertificate(cert.Raw); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.crt")
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 32)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	client, secret, err := newClient(settings{configFile: configFile{CAFile: ca, TokenFile: token}, RequestLimit: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return client, secret
}

func TestTLSUploadAndStatus(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusCreated)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 32) {
			t.Error("bad auth")
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer server.Close()
	client, token := testClient(t, server)
	if err := upload(context.Background(), client, server.URL, token, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{http.StatusNoContent, http.StatusAccepted, http.StatusForbidden} {
		status.Store(int32(code))
		if err := upload(context.Background(), client, server.URL, token, []byte("{}")); err == nil {
			t.Fatalf("accepted HTTP %d", code)
		}
	}
	if _, err := http.DefaultClient.Get(server.URL); err == nil {
		t.Fatal("untrusted cert accepted")
	}
}

func TestLockReleasedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.lock")
	first, err := acquireRunLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := acquireRunLock(path); err == nil {
		second.Close()
		t.Fatal("parallel lock acquired")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireRunLock(path)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	second.Close()
}

func TestBoundedOutputAndExclusions(t *testing.T) {
	var output = boundedBuffer{limit: 4}
	if _, err := output.Write([]byte("12345")); err == nil || output.String() != "1234" {
		t.Fatal("size limit not applied")
	}
	cfg := settings{configFile: configFile{ScanPath: filepath.FromSlash("/opt"), StateDir: filepath.FromSlash("/opt/probe/state"), TokenFile: filepath.FromSlash("/opt/probe/token")}}
	excludes := strings.Join(scanExclusions(cfg), "\n")
	if !strings.Contains(excludes, "./probe/token") || !strings.Contains(excludes, "./probe/state/**") {
		t.Fatal(excludes)
	}
	if err := validateSBOM(json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)); err != nil {
		t.Fatal(err)
	}
	if err := validateSBOM(json.RawMessage(`{"format":"other"}`)); err == nil {
		t.Fatal("bad SBOM accepted")
	}
}

func TestPendingReportResentWithoutSyft(t *testing.T) {
	dir := t.TempDir()
	machineID, err := getMachineID(dir)
	if err != nil {
		t.Fatal(err)
	}
	reportID, _ := newID()
	data, _ := json.Marshal(report{ClientID: "client-a", MachineID: machineID, ReportID: reportID})
	path := filepath.Join(dir, "pending-report.json")
	if err := writeAtomic(path, data); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusCreated) }))
	defer server.Close()
	client, token := testClient(t, server)
	cfg := settings{configFile: configFile{ClientID: "client-a", StateDir: dir, SyftPath: "does-not-exist"}, Endpoint: server.URL}
	if err := collectAndSend(context.Background(), cfg, machineID, client, token); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("pending file retained: %v", err)
	}
	if runtime.GOOS == "windows" && defaultScanPath() == "/" {
		t.Fatal("bad Windows default")
	}
}
