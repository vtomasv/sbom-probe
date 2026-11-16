#!/bin/sh
set -eu
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }

usage() {
    printf 'Uso: sudo sh %s --deployment DIRECTORIO\n     sudo sh %s --uninstall\n' "$0" "$0"
}

case "${1:-}" in
    --deployment) [ "$#" -eq 2 ] || { usage; exit 2; } ;;
    --uninstall) [ "$#" -eq 1 ] || { usage; exit 2; } ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
[ "$(id -u)" -eq 0 ] || fail 'Ejecuta el instalador con sudo.'

bundle=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
system=$(uname -s)
case "$system" in
    Linux)
        target_os=linux
        bin_dir=/opt/sbom-probe
        config_dir=/etc/sbom-probe
        service_file=/etc/systemd/system/sbom-probe.service
        root_group=root
        command -v systemctl >/dev/null || fail 'La instalación automática en Linux requiere systemd.'
        [ -d /run/systemd/system ] || fail 'systemd debe estar en ejecución.'
        ;;
    Darwin)
        target_os=darwin
        config_dir='/Library/Application Support/SBOM Probe'
        bin_dir="$config_dir/bin"
        service_file=/Library/LaunchDaemons/org.sbom-probe.agent.plist
        service_label=org.sbom-probe.agent
        root_group=wheel
        ;;
    *) fail "Sistema no compatible: $system" ;;
esac

stop_service() {
    [ -f "$service_file" ] || return 0
    if [ "$system" = Linux ]; then
        systemctl stop sbom-probe.service
    elif launchctl print "system/$service_label" >/dev/null 2>&1; then
        launchctl bootout "system/$service_label"
    fi
}

if [ "$1" = --uninstall ]; then
    if [ -f "$service_file" ]; then
        stop_service
        if [ "$system" = Linux ]; then systemctl disable sbom-probe.service; fi
        rm -f -- "$service_file"
        if [ "$system" = Linux ]; then systemctl daemon-reload; fi
    fi
    for file in config.json ca.crt client.token client.crt client.key; do
        rm -f -- "$config_dir/$file"
    done
    for file in sbom-probe syft install.sh; do
        rm -f -- "$bin_dir/$file"
    done
    printf 'Sonda desinstalada. La identidad y los datos pendientes siguen en %s/state.\n' "$config_dir"
    exit 0
fi

case "$(uname -m)" in
    x86_64) cpu=amd64 ;;
    arm64|aarch64) cpu=arm64 ;;
    *) fail 'Arquitectura no compatible.' ;;
esac
[ -f "$bundle/target.txt" ] && [ "$(cat "$bundle/target.txt")" = "${target_os}_${cpu}" ] || fail "Usa el paquete ${target_os}_${cpu}."
deployment=$(CDPATH= cd -- "$2" && pwd -P) || fail 'No se encontró el directorio de despliegue.'
for file in config.json ca.crt client.token; do
    [ -f "$deployment/$file" ] || fail "Falta $deployment/$file."
done
if [ -f "$deployment/client.crt" ] || [ -f "$deployment/client.key" ]; then
    [ -f "$deployment/client.crt" ] && [ -f "$deployment/client.key" ] || fail 'Se requieren client.crt y client.key para mTLS.'
fi

install -d -o root -g "$root_group" -m 0700 "$config_dir"
install -d -o root -g "$root_group" -m 0755 "$bin_dir"
stage=$(mktemp -d "$config_dir/.install.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
trap 'exit 1' HUP INT TERM

copy_deployment() {
    origin=$1
    destination=$2
    for file in config.json ca.crt client.token client.crt client.key; do
        if [ -f "$origin/$file" ]; then
            install -o root -g "$root_group" -m 0600 "$origin/$file" "$destination/$file"
        fi
    done
}

copy_deployment "$deployment" "$stage"
install -m 0755 "$bundle/sbom-probe" "$bundle/syft" "$stage"
if ! "$stage/sbom-probe" init -config "$stage/config.json" >/dev/null; then
    fail 'La configuración de despliegue no es válida.'
fi

stop_service
for file in sbom-probe syft install.sh; do
    install -o root -g "$root_group" -m 0755 "$bundle/$file" "$bin_dir/$file"
done
copy_deployment "$stage" "$config_dir"
if [ ! -f "$stage/client.key" ]; then rm -f -- "$config_dir/client.crt" "$config_dir/client.key"; fi
"$bin_dir/sbom-probe" init -config "$config_dir/config.json"

if [ "$system" = Linux ]; then
    install -o root -g "$root_group" -m 0644 "$bundle/sbom-probe.service" "$service_file"
    systemctl daemon-reload
    systemctl enable --now sbom-probe.service
else
    install -d -o root -g "$root_group" -m 0700 "$config_dir/logs"
    install -o root -g "$root_group" -m 0644 "$bundle/org.sbom-probe.agent.plist" "$service_file"
    launchctl enable "system/$service_label"
    launchctl bootstrap system "$service_file"
fi
printf 'Sonda instalada. Configuración en %s/config.json.\n' "$config_dir"
