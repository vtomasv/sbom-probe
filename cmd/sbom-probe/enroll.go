package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type profile struct {
	Version     int      `json:"version"`
	ServerURL   string   `json:"server_url"`
	ClientID    string   `json:"client_id"`
	Metadata    metadata `json:"metadata"`
	CA          string   `json:"ca"`
	Certificate string   `json:"certificate"`
	Key         string   `json:"key"`
	Token       string   `json:"token"`
}

func enrollCommand(args []string) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	path := flags.String("profile", "", "archivo privado del equipo")
	target := flags.String("config", "config.json", "configuración de destino")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 {
		return errors.New("use enroll -profile equipo.sbom -config config.json")
	}
	return enroll(*path, *target)
}

func enroll(source, target string) error {
	data, err := readFileLimited(source, 512<<10)
	if err != nil {
		return err
	}
	var p profile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || dec.Decode(new(any)) != io.EOF || p.Version != 1 || p.Certificate == "" || p.Key == "" {
		return errors.New("perfil de inscripción o identidad mTLS inválidos")
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	lock, err := acquireRunLock(filepath.Join(dir, "enroll.lock"))
	if err != nil {
		return fmt.Errorf("inscripción ocupada: %w", err)
	}
	defer lock.Close()
	state := "state"
	if previous, err := readConfig(target); err == nil {
		if previous.ClientID != p.ClientID {
			return errors.New("el equipo ya está inscrito para otro cliente")
		}
		state = previous.StateDir
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staging, err := os.MkdirTemp(dir, "perfil-")
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			os.RemoveAll(staging)
		}
	}()
	relative := func(name string) string { return filepath.Join(filepath.Base(staging), name) }
	for name, value := range map[string]string{"ca.crt": p.CA, "client.crt": p.Certificate, "client.key": p.Key, "client.token": p.Token} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte(value), 0600); err != nil {
			return err
		}
	}
	cfg := configFile{InventoryMode: "native", ServerURL: p.ServerURL, ClientID: p.ClientID, TokenFile: relative("client.token"), CAFile: relative("ca.crt"), ClientCertFile: relative("client.crt"), ClientKeyFile: relative("client.key"), StateDir: state, Metadata: p.Metadata}
	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	pending, err := os.CreateTemp(dir, ".enroll-*")
	if err != nil {
		return err
	}
	defer os.Remove(pending.Name())
	if _, err = pending.Write(encoded); err == nil {
		err = pending.Sync()
	}
	closeErr := pending.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	checked, err := readConfig(pending.Name())
	if err != nil {
		return err
	}
	client, _, err := newClient(checked)
	if err != nil {
		return err
	}
	client.CloseIdleConnections()
	if err := os.Rename(pending.Name(), target); err != nil {
		return err
	}
	published = true
	return nil
}
