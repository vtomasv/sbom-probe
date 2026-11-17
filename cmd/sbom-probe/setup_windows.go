package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed windows_install.ps1
var installScript string

func powershell() string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}
func removeSetup() error           { return windowsInstaller("uninstall", nil) }
func runSetup(args []string) error { return windowsInstaller("install", args) }
func windowsInstaller(action string, args []string) error {
	if len(args) > 1 {
		return errors.New("uso: sbom-probe-setup.exe install [equipo.sbom]")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	profile := filepath.Join(filepath.Dir(self), "equipo.sbom")
	if len(args) == 1 {
		profile, err = filepath.Abs(args[0])
		if err != nil {
			return err
		}
	}
	cmd := exec.Command(powershell(), "-NoProfile", "-STA", "-Command", installScript)
	cmd.Env = append(os.Environ(), "SBOM_SETUP_ACTION="+action, "SBOM_SETUP_SOURCE="+self, "SBOM_SETUP_PROFILE="+profile)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// Read both native registry views, including on ARM64. Do not invoke Win32_Product,
// which can trigger MSI repairs. Emit UTF-8 so product names survive the pipe.
func windowsPrograms(ctx context.Context) ([]inventoryComponent, error) {
	const script = `$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$items=foreach($view in 'Registry64','Registry32'){
 $reg=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine',$view)
 try {
  $list=$reg.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
  if($null -ne $list){try{foreach($id in $list.GetSubKeyNames()){
   $product=$list.OpenSubKey($id); if($null -eq $product){continue}
   try{$name=$product.GetValue('DisplayName')
    if($name){[pscustomobject]@{name=[string]$name;version=[string]$product.GetValue('DisplayVersion');publisher=[string]$product.GetValue('Publisher')}}
   }finally{$product.Dispose()}
  }}finally{$list.Dispose()}}
 }finally{$reg.Dispose()}
}
ConvertTo-Json -InputObject @($items | Sort-Object name,version,publisher -Unique) -Compress`
	cmd := exec.CommandContext(ctx, powershell(), "-NoProfile", "-NonInteractive", "-Command", script)
	output := &boundedBuffer{limit: maxSBOMBytes}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("leer programas instalados del registro: %w", err)
	}
	var items []inventoryComponent
	if err := json.Unmarshal(output.Bytes(), &items); err != nil {
		return nil, err
	}
	for i := range items {
		items[i].Type = "application"
		items[i].Name = strings.TrimSpace(items[i].Name)
	}
	return items, nil
}
