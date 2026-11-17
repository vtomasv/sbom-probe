package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	if err := execute(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func execute(args []string) error {
	if len(args) == 0 && strings.HasPrefix(strings.ToLower(filepath.Base(os.Args[0])), "sbom-probe-setup") {
		return runSetup(nil)
	}
	if len(args) == 1 && args[0] == "uninstall" {
		return removeSetup()
	}
	if len(args) > 0 && args[0] == "install" {
		return runSetup(args[1:])
	}
	if len(args) > 0 && args[0] == "enroll" {
		return enrollCommand(args[1:])
	}
	if len(args) == 0 {
		return errors.New("uso: sbom-probe enroll -profile equipo.sbom -config archivo.json, sbom-probe init|run -config archivo.json [-watch], o sbom-probe version")
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Println(version)
		return nil
	}
	if args[0] != "init" && args[0] != "run" {
		return fmt.Errorf("comando desconocido %q", args[0])
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	defaultConfig := os.Getenv("SBOM_PROBE_CONFIG")
	if defaultConfig == "" {
		defaultConfig = "config.json"
	}
	path := flags.String("config", defaultConfig, "Ruta del archivo JSON")
	watch := flags.Bool("watch", false, "Repetir según interval")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if len(flags.Args()) > 0 {
		return errors.New("argumentos posicionales inesperados")
	}
	cfg, err := readConfig(*path)
	if err != nil {
		return err
	}
	client, token, err := newClient(cfg)
	if err != nil {
		return err
	}
	id, err := getMachineID(cfg.StateDir)
	if err != nil {
		return err
	}
	if args[0] == "init" {
		fmt.Println(id)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	for {
		err := collectAndSend(ctx, cfg, id, client, token)
		if ctx.Err() != nil {
			return nil
		}
		if !*watch {
			return err
		}
		if err != nil {
			log.Printf("falló el ciclo: %v", err)
		}
		timer := time.NewTimer(cfg.ScanInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
