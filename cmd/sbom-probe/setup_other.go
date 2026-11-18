//go:build !windows

package main

import (
	"context"
	"errors"
)

func runSetup(args []string) error {
	return errors.New("en Debian y Ubuntu instale el paquete .deb y ejecute sbom-probe-activar")
}
func windowsPrograms(context.Context) ([]inventoryComponent, error) {
	return nil, errors.New("el registro de Windows no está disponible")
}

func removeSetup() error {
	return errors.New("use el gestor de paquetes de Linux para retirar la sonda")
}
