# Instalación de la sonda SBOM

Cada paquete incluye la sonda, Syft v1.57.2 y el instalador. La instalación se
puede ejecutar sin internet. La sonda necesita conectividad con el servidor al
escanear y reportar.

| Sistema | Arquitecturas | Automatización |
| --- | --- | --- |
| Linux con systemd | x86-64 (`amd64`), ARM64 (`arm64`) | Servicio `sbom-probe.service` |
| macOS | Intel (`amd64`), Apple Silicon (`arm64`) | LaunchDaemon `org.sbom-probe.agent` |
| Windows con PowerShell 5.1 y Programador de tareas | x86-64 (`amd64`), ARM64 (`arm64`) | Tarea `SBOM Probe` |

## Preparar la configuración del cliente

Prepara un directorio con estos archivos y distribúyelo por el canal autorizado de
aprovisionamiento de cada cliente. Los paquetes de instalación se pueden distribuir por separado.

| Archivo | Contenido |
| --- | --- |
| `config.json` | Copia de `deployment.example.json` con la URL, el `client_id` y las etiquetas del equipo. |
| `ca.crt` | Certificado público de la autoridad autofirmada que emitió el certificado TLS del servidor. |
| `client.token` | Token del cliente registrado en el servidor, como texto plano en una línea. |
| `client.crt`, `client.key` | Par de certificado y clave privada del cliente cuando se usa mTLS. Incluye `"client_cert_file": "client.crt"` y `"client_key_file": "client.key"` en `config.json`. |

Conserva `token_file` y `ca_file` con sus nombres relativos del ejemplo. Omite
`state_dir` y `syft_path` para que la sonda use la identidad persistente y el
Syft incluidos en la instalación. Puedes ajustar `scan_path` (ruta absoluta), `scan_excludes`,
`interval`, `scan_timeout`, `request_timeout` y `metadata` para cada ambiente.

Ejecuta el instalador después de aprovisionar o clonar la máquina. El instalador
crea un UUID local, conserva ese UUID en las actualizaciones y arranca la sonda
con la cuenta de sistema para poder leer el mayor alcance posible. El alcance
del inventario depende de los catalogadores de Syft, los caminos elegidos y los
permisos del sistema. En macOS, las rutas protegidas por TCC pueden requerir
Full Disk Access administrado por el cliente.

## Linux y macOS

Verifica la descarga con `SHA256SUMS` y extrae el `.tar.gz` del sistema y
arquitectura correspondientes. Desde la carpeta extraída, ejecuta:

```sh
sudo sh ./install.sh --deployment /ruta/al/despliegue
```

En Linux, consulta `sudo journalctl -u sbom-probe.service`. La configuración
queda en `/etc/sbom-probe`. En macOS, queda en `/Library/Application Support/SBOM Probe`,
donde `logs` contiene la salida de la sonda. Para aplicar cambios en la
configuración, repite el comando de instalación con los archivos actualizados.

Para desinstalar, ejecuta `sudo sh ./install.sh --uninstall` desde el paquete
extraído. También puedes usar `/opt/sbom-probe/install.sh` en Linux o
`/Library/Application Support/SBOM Probe/bin/install.sh` en macOS. Se conservan
la identidad y los reportes pendientes en el directorio `state` para reinstalar.

## Windows

Verifica el `.zip` con `Get-FileHash` y el valor publicado en `SHA256SUMS`. Extrae
el archivo y abre PowerShell como administrador en la carpeta extraída. Ejecuta:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Deployment 'C:\ruta\al\despliegue'
```

La configuración queda en `C:\ProgramData\SBOM Probe`. La salida se almacena
en `logs\probe.log`. Para actualizar, repite la instalación con el nuevo
paquete o directorio de despliegue. Para desinstalar, usa `-Uninstall` en lugar
de `-Deployment`, desde el paquete extraído o desde el directorio instalado.
La identidad y los reportes pendientes se conservan en `state`.

## Construir paquetes

Los paquetes de prueba se generan en GitHub Actions en los cambios de `main`.
Las etiquetas `v*` generan una GitHub Release con los mismos archivos y sus
hashes. Para construir localmente desde la raíz del repositorio, usa Go (la
versión está en `go.mod`), Python 3.9 o posterior y acceso a GitHub:

```sh
python3 installer/package.py --version 0.1.0
```

El empaquetado comprueba el SHA-256 fijado del manifiesto de Syft v1.57.2 y el
SHA-256 de cada archivo de distribución que se copia al paquete. La caché se
puede rellenar con esos mismos archivos verificados para compilar sin descargas.
El resultado queda en `dist/`. Usa `--target linux_arm64`, por ejemplo, para
construir una sola plataforma. Los paquetes distribuidos carecen de firma
Authenticode, firma Developer ID y notarización. Puedes aplicar la firma y la
política de distribución de tu organización a los binarios y scripts finales.
