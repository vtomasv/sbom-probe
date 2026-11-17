package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"
)

var slug = regexp.MustCompile(`^[A-Za-z0-9][-A-Za-z0-9_.]{0,63}$`)

type metadata struct {
	Group      string            `json:"group,omitempty"`
	Zone       string            `json:"zone,omitempty"`
	Department string            `json:"department,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

type configFile struct {
	InventoryMode  string   `json:"inventory_mode,omitempty"`
	ServerURL      string   `json:"server_url"`
	ClientID       string   `json:"client_id"`
	TokenFile      string   `json:"token_file"`
	CAFile         string   `json:"ca_file"`
	ClientCertFile string   `json:"client_cert_file"`
	ClientKeyFile  string   `json:"client_key_file"`
	StateDir       string   `json:"state_dir"`
	SyftPath       string   `json:"syft_path"`
	ScanPath       string   `json:"scan_path"`
	ScanExcludes   []string `json:"scan_excludes"`
	ScanTimeout    string   `json:"scan_timeout"`
	RequestTimeout string   `json:"request_timeout"`
	Interval       string   `json:"interval"`
	Metadata       metadata `json:"metadata"`
}

type settings struct {
	configFile
	ConfigPath   string
	Endpoint     string
	ScanLimit    time.Duration
	RequestLimit time.Duration
	ScanInterval time.Duration
}

func readConfig(path string) (settings, error) {
	var cfg settings
	absolute, err := filepath.Abs(path)
	if err != nil {
		return cfg, err
	}
	cfg.ConfigPath = absolute

	content, err := readFileLimited(absolute, 128*1024)
	if err != nil {
		return cfg, fmt.Errorf("leer configuración: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg.configFile); err != nil {
		return cfg, fmt.Errorf("configuración JSON: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("la configuración debe contener un solo objeto JSON")
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	if err := cfg.resolvePaths(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (cfg *settings) validate() error {
	if cfg.InventoryMode != "" && cfg.InventoryMode != "syft" && cfg.InventoryMode != "native" {
		return errors.New("inventory_mode debe ser native o syft")
	}
	endpoint, err := url.Parse(cfg.ServerURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawPath != "" ||
		strings.Contains(cfg.ServerURL, "#") {
		return errors.New("server_url debe ser una URL base HTTPS sin credenciales, consulta ni fragmento")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/v1/reports"
	cfg.Endpoint = endpoint.String()

	if !slug.MatchString(cfg.ClientID) {
		return errors.New("client_id debe comenzar con letra o número y tener hasta 64 caracteres alfanuméricos, '.', '_' o '-'")
	}
	if cfg.TokenFile == "" || cfg.CAFile == "" {
		return errors.New("token_file y ca_file son obligatorios")
	}
	if (cfg.ClientCertFile == "") != (cfg.ClientKeyFile == "") {
		return errors.New("client_cert_file y client_key_file deben configurarse juntos")
	}
	for _, entry := range []struct {
		name string
		text string
	}{
		{"group", cfg.Metadata.Group},
		{"zone", cfg.Metadata.Zone},
		{"department", cfg.Metadata.Department},
	} {
		if len(entry.text) > 128 || strings.IndexFunc(entry.text, unicode.IsControl) >= 0 {
			return fmt.Errorf("metadata.%s admite hasta 128 bytes", entry.name)
		}
	}
	if len(cfg.Metadata.Tags) > 32 {
		return errors.New("metadata.tags admite hasta 32 etiquetas")
	}
	for key, value := range cfg.Metadata.Tags {
		if !slug.MatchString(key) || strings.TrimSpace(value) == "" || len(value) > 256 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("etiqueta inválida %q: se requiere una clave tipo client_id y texto de hasta 256 bytes", key)
		}
	}
	for _, pattern := range cfg.ScanExcludes {
		if strings.TrimSpace(pattern) == "" {
			return errors.New("scan_excludes contiene un patrón vacío")
		}
	}

	for _, entry := range []struct {
		name     string
		text     string
		fallback time.Duration
		value    *time.Duration
	}{
		{"scan_timeout", cfg.ScanTimeout, 45 * time.Minute, &cfg.ScanLimit},
		{"request_timeout", cfg.RequestTimeout, 2 * time.Minute, &cfg.RequestLimit},
		{"interval", cfg.Interval, 24 * time.Hour, &cfg.ScanInterval},
	} {
		*entry.value = entry.fallback
		if entry.text == "" {
			continue
		}
		parsed, err := time.ParseDuration(entry.text)
		if err != nil || parsed <= 0 {
			return fmt.Errorf("%s debe contener una duración positiva, por ejemplo 30m", entry.name)
		}
		*entry.value = parsed
	}
	return nil
}

func (cfg *settings) resolvePaths() error {
	if cfg.StateDir == "" {
		cfg.StateDir = "state"
	}
	if cfg.ScanPath == "" {
		cfg.ScanPath = defaultScanPath()
	}
	if cfg.SyftPath == "" {
		executable, err := os.Executable()
		if err != nil {
			return fmt.Errorf("localizar sonda: %w", err)
		}
		syft := "syft"
		if runtime.GOOS == "windows" {
			syft += ".exe"
		}
		cfg.SyftPath = filepath.Join(filepath.Dir(executable), syft)
	}

	base := filepath.Dir(cfg.ConfigPath)
	for _, value := range []*string{&cfg.TokenFile, &cfg.CAFile, &cfg.ClientCertFile, &cfg.ClientKeyFile, &cfg.StateDir, &cfg.SyftPath, &cfg.ScanPath} {
		if *value == "" {
			continue
		}
		if !filepath.IsAbs(*value) {
			if runtime.GOOS == "windows" && strings.HasPrefix(*value, string(filepath.Separator)) {
				return fmt.Errorf("incluya la unidad en la ruta de Windows %q", *value)
			}
			if filepath.VolumeName(*value) != "" {
				return fmt.Errorf("se requiere una ruta absoluta o relativa al archivo de configuración: %q", *value)
			}
			*value = filepath.Join(base, *value)
		}
		*value = filepath.Clean(*value)
	}
	if len(cfg.ScanPath) > 2048 {
		return errors.New("scan_path admite hasta 2048 bytes")
	}
	return nil
}

func defaultScanPath() string {
	if runtime.GOOS == "windows" {
		volume := os.Getenv("SystemDrive")
		if volume == "" {
			volume = "C:"
		}
		return volume + string(filepath.Separator)
	}
	return string(filepath.Separator)
}

func readFileLimited(path string, max int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > max {
		return nil, fmt.Errorf("%s supera el tamaño permitido", path)
	}
	return content, nil
}
