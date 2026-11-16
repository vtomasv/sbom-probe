# SBOM Probe

Sonda multiplataforma que ejecuta [Anchore Syft](https://github.com/anchore/syft), genera inventarios CycloneDX JSON y los reporta al servicio SBOM por HTTPS.

[Instalación de la sonda](installer/README.md)

## Configuración

El instalador recibe un paquete de despliegue con `config.json`, `client.token`, `ca.crt` y los certificados opcionales de cliente. El token identifica al cliente en el servidor y debe mantenerse privado. El certificado del servidor se valida con la CA configurada y el nombre DNS o IP de `server_url`.

```json
{
  "server_url": "https://sbom.example.internal:8443",
  "client_id": "cliente-a",
  "token_file": "client.token",
  "ca_file": "ca.crt",
  "state_dir": "state",
  "syft_path": "/opt/sbom-probe/syft",
  "scan_path": "/",
  "scan_excludes": ["./mnt/**", "./media/**"],
  "scan_timeout": "45m",
  "request_timeout": "2m",
  "interval": "24h",
  "metadata": {
    "group": "servidores",
    "zone": "santiago",
    "department": "tecnologia",
    "tags": {"ambiente": "produccion", "equipo": "operaciones"}
  }
}
```

Para autenticación mutua TLS, agrega conjuntamente `client_cert_file` y `client_key_file` al JSON. Todas las rutas relativas se resuelven respecto del directorio de `config.json`. En Windows usa rutas absolutas con unidad, por ejemplo `C:\\`. El escaneo predeterminado cubre `/` en Linux/macOS y la unidad del sistema en Windows. Se pueden crear configuraciones separadas para otras unidades.

`syft_path` predetermina al binario Syft junto a la sonda. `state_dir` predetermina a `state` junto a la configuración. Los tiempos deben ser duraciones positivas, como `30m` o `24h`. Grupo, zona y departamento admiten hasta 128 bytes cada uno. Se admiten 32 etiquetas con claves tipo identificador de hasta 64 caracteres y valores de hasta 256 bytes.

## Ejecución

```sh
sbom-probe init -config /etc/sbom-probe/config.json
sbom-probe run -config /etc/sbom-probe/config.json
sbom-probe run -config /etc/sbom-probe/config.json -watch
sbom-probe version
```

`SBOM_PROBE_CONFIG` también permite indicar la configuración. El modo `init` valida los archivos de autenticación y crea la identidad. Cada instalación genera un UUID v4 criptográficamente aleatorio, persistido en `state_dir/machine-id`. Las actualizaciones conservan este archivo. Las imágenes clonadas deben aprovisionarse antes de ejecutar `init`, o excluir `state_dir` de la imagen base. Cada sonda de un contenedor usa su propio volumen persistente.

El modo `run` realiza un ciclo y devuelve un código de error ante fallos. `-watch` repite según `interval` y continúa después de un ciclo fallido. Se atienden SIGINT y SIGTERM y los bloqueos de ejecución se liberan automáticamente al terminar el proceso.

## Reportes y reintentos

La sonda envía `POST /v1/reports` con `Authorization: Bearer <token>` y el contrato de sobre versión 1. Incluye identificador de reporte y máquina, cliente, fecha UTC, hostname, sistema, arquitectura, ruta de origen, metadatos y el documento CycloneDX.

Antes del envío guarda el reporte de forma atómica en `state_dir/pending-report.json`. Si se interrumpe la comunicación conserva el mismo `report_id` y payload para repetirlo con la idempotencia del servidor. Un ciclo pendiente se entrega antes de generar otro inventario. Hay hasta tres intentos para errores de comunicación, HTTP 429 y HTTP 5xx. HTTP 200 o 201 confirma la recepción. Las respuestas 4xx requieren corregir la configuración o el reporte y lo conservan en disco.

El documento generado admite hasta 60 MiB. El servidor debe aceptar el sobre completo, cuyo límite predeterminado es 64 MiB. El archivo pendiente requiere espacio local equivalente al inventario.

## Alcance del inventario

Se invoca Syft con `--select-catalogers installed`, `--output cyclonedx-json`, configuración controlada y enriquecimiento externo desactivado. La sonda elimina variables `SYFT_*` heredadas y desactiva la comprobación de actualizaciones. Excluye `proc`, `sys`, `dev`, `run`, su directorio de estado, configuración y archivos de credenciales cuando están dentro de la raíz escaneada.

La cobertura depende de los catalogadores de Syft, los permisos de lectura y la ruta seleccionada. Linux permite inventariar las bases de paquetes y ecosistemas compatibles. Windows y macOS utilizan los catalogadores compatibles con archivos y gestores detectables en el filesystem. Cada despliegue debe contrastar los paquetes detectados con su inventario esperado. Los contenedores del laboratorio inventarían sus propios sistemas de archivos.

## Desarrollo

```sh
go test -race ./...
go build -o sbom-probe ./cmd/sbom-probe
```

El runtime usa la biblioteca estándar de Go. Los paquetes de instalación incluyen una versión fijada de Syft, su licencia y los artefactos de terceros asociados. Consulta el flujo de publicación y los instaladores para Linux, macOS y Windows.
