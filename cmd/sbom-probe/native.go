package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type inventoryComponent struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Publisher string `json:"publisher,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

func nativeInventory(ctx context.Context, root string) (json.RawMessage, error) {
	var packages []inventoryComponent
	var err error
	switch runtime.GOOS {
	case "windows":
		packages, err = windowsPrograms(ctx)
	case "linux":
		packages, err = debianInventory(ctx, root)
	default:
		return nil, errors.New("el inventario nativo requiere Windows o Debian/Ubuntu; use el modo syft en este sistema")
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(packages, func(i, j int) bool {
		a, b := packages[i], packages[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.PURL != b.PURL {
			return a.PURL < b.PURL
		}
		return a.Publisher < b.Publisher
	})
	document := struct {
		Format     string               `json:"bomFormat"`
		Spec       string               `json:"specVersion"`
		Version    int                  `json:"version"`
		Components []inventoryComponent `json:"components"`
	}{"CycloneDX", "1.6", 1, packages}
	content, err := json.Marshal(document)
	if len(content) > maxSBOMBytes {
		return nil, errors.New("el inventario supera el tamaño permitido")
	}
	return content, err
}

func debianInventory(ctx context.Context, root string) ([]inventoryComponent, error) {
	status, err := os.Open(filepath.Join(root, "var/lib/dpkg/status"))
	if err != nil {
		return nil, fmt.Errorf("abrir el inventario dpkg: %w", err)
	}
	defer status.Close()
	file, err := os.Open(filepath.Join(root, "etc/os-release"))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	release := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		k, v, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			release[k] = strings.Trim(v, "\"'")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if release["ID"] == "" {
		return nil, errors.New("falta ID en os-release")
	}
	return readDpkg(ctx, status, release["ID"], release["VERSION_ID"])
}

func readDpkg(ctx context.Context, source io.Reader, distro, release string) ([]inventoryComponent, error) {
	packages := make([]inventoryComponent, 0)
	fields := make(map[string]string)
	finish := func() {
		if fields["Status"] == "install ok installed" && fields["Package"] != "" && fields["Version"] != "" {
			q := url.Values{}
			if fields["Architecture"] != "" {
				q.Set("arch", fields["Architecture"])
			}
			if release != "" {
				q.Set("distro", distro+"-"+release)
			}
			purl := "pkg:deb/" + url.PathEscape(distro) + "/" + url.PathEscape(fields["Package"]) + "@" + url.PathEscape(fields["Version"])
			if query := q.Encode(); query != "" {
				purl += "?" + query
			}
			packages = append(packages, inventoryComponent{Type: "library", Name: fields["Package"], Version: fields["Version"], PURL: purl})
		}
		clear(fields)
	}
	scanner := bufio.NewScanner(source)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := scanner.Text()
		if line == "" {
			finish()
			continue
		}
		k, v, ok := strings.Cut(line, ": ")
		if ok {
			switch k {
			case "Package", "Status", "Architecture", "Version":
				fields[k] = v
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	finish()
	return packages, nil
}
