package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDpkgOnlyInstalled(t *testing.T) {
	status := "Package: borrado\nStatus: deinstall ok config-files\nVersion: 1\n\nPackage: demo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.3+1\n"
	got, err := readDpkg(context.Background(), strings.NewReader(status), "debian", "13")
	if err != nil || len(got) != 1 || got[0].Name != "demo" || !strings.Contains(got[0].PURL, "distro=debian-13") {
		t.Fatalf("inventario: %v %v", got, err)
	}
}
func TestEnrollValidatesBeforePublishing(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	cert := server.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	crt := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	private := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	if _, err := tls.X509KeyPair([]byte(crt), []byte(private)); err != nil {
		t.Fatal(err)
	}
	p := profile{Version: 1, ServerURL: server.URL, ClientID: "cliente", CA: crt, Certificate: crt, Key: private, Token: strings.Repeat("a", 32)}
	dir := t.TempDir()
	source, target := filepath.Join(dir, "equipo.sbom"), filepath.Join(dir, "config.json")
	write := func() {
		b, _ := json.Marshal(p)
		if err := os.WriteFile(source, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if err := enroll(source, target); err != nil {
		t.Fatal(err)
	}
	cfg, err := readConfig(target)
	if err != nil || cfg.InventoryMode != "native" {
		t.Fatal(err)
	}
	id, err := getMachineID(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(target)
	p.Key = "dañada"
	write()
	if err := enroll(source, target); err == nil {
		t.Fatal("clave inválida aceptada")
	}
	current, _ := os.ReadFile(target)
	if string(current) != string(original) {
		t.Fatal("configuración dañada")
	}
	p.Key = private
	write()
	if err := enroll(source, target); err != nil {
		t.Fatal(err)
	}
	cfg, err = readConfig(target)
	if err != nil {
		t.Fatal(err)
	}
	if id2, err := getMachineID(cfg.StateDir); err != nil || id2 != id {
		t.Fatal("identidad rotada")
	}
}
