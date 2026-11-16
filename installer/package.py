#!/usr/bin/env python3
"""Build offline installer bundles with a verified Anchore Syft binary."""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile


INSTALLER = Path(__file__).resolve().parent
PROJECT = INSTALLER.parent
SYFT_VERSION = "1.57.2"
SYFT_MANIFEST_SHA256 = "73e421a829285be9a2af92d56ff93d8287c34f0515eaac7c2081f06031cab4bd"
SYFT_DOWNLOAD_URL = f"https://github.com/anchore/syft/releases/download/v{SYFT_VERSION}"
TARGETS = (
    "linux_amd64",
    "linux_arm64",
    "darwin_amd64",
    "darwin_arm64",
    "windows_amd64",
    "windows_arm64",
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def asset(name, expected_hash, cache):
    destination = cache / name
    if destination.is_file() and sha256(destination) == expected_hash:
        return destination
    with tempfile.NamedTemporaryFile(prefix=".download-", dir=cache, delete=False) as pending:
        staged = Path(pending.name)
        try:
            url = f"{SYFT_DOWNLOAD_URL}/{name}"
            with urllib.request.urlopen(url, timeout=90) as response:
                shutil.copyfileobj(response, pending)
            pending.close()
            if sha256(staged) != expected_hash:
                raise ValueError(f"SHA-256 incorrecto para {name}")
            staged.replace(destination)
        finally:
            staged.unlink(missing_ok=True)
    return destination


def checksums(cache):
    name = f"syft_{SYFT_VERSION}_checksums.txt"
    manifest = asset(name, SYFT_MANIFEST_SHA256, cache)
    hashes = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})\s+\*?([^\s]+)", line)
        if not match:
            raise ValueError(f"Formato inesperado en {name}")
        digest, filename = match.groups()
        hashes[filename] = digest
    return hashes


def extract_syft(archive_path, bundle, windows):
    executable = "syft.exe" if windows else "syft"
    names = {executable: executable, "LICENSE": "SYFT-LICENSE", "NOTICE": "SYFT-NOTICE"}
    extracted = set()

    def copy_entry(path, source):
        name = names[PurePosixPath(path).name]
        if name in extracted:
            raise ValueError(f"Archivo duplicado en el paquete de Syft: {name}")
        with source, (bundle / name).open("wb") as destination:
            shutil.copyfileobj(source, destination)
        extracted.add(name)

    if windows:
        with zipfile.ZipFile(archive_path) as archive:
            for entry in archive.infolist():
                if not entry.is_dir() and PurePosixPath(entry.filename).name in names:
                    copy_entry(entry.filename, archive.open(entry))
    else:
        with tarfile.open(archive_path, "r:gz") as archive:
            for entry in archive:
                if entry.isfile() and PurePosixPath(entry.name).name in names:
                    copy_entry(entry.name, archive.extractfile(entry))

    if not {executable, "SYFT-LICENSE"}.issubset(extracted):
        raise ValueError(f"El paquete publicado no contiene {executable} y LICENSE")
    (bundle / executable).chmod(0o755)


def build_package(target, release, manifest, cache, dist):
    system, architecture = target.split("_", 1)
    windows = system == "windows"
    suffix = ".zip" if windows else ".tar.gz"
    asset_name = f"syft_{SYFT_VERSION}_{target}{suffix}"
    if asset_name not in manifest:
        raise ValueError(f"El manifiesto oficial omite {asset_name}")
    safe_syft = asset(asset_name, manifest[asset_name], cache)

    name = f"sbom-probe_{release}_{target}"
    with tempfile.TemporaryDirectory(prefix="sbom-probe-release-") as workspace:
        bundle = Path(workspace) / name
        bundle.mkdir()
        probe = bundle / ("sbom-probe.exe" if windows else "sbom-probe")
        env = dict(os.environ, CGO_ENABLED="0", GOOS=system, GOARCH=architecture)
        subprocess.run(
            ["go", "build", "-trimpath", "-ldflags", f"-X main.version={release}", "-o", str(probe), "./cmd/sbom-probe"],
            cwd=PROJECT,
            env=env,
            check=True,
        )
        extract_syft(safe_syft, bundle, windows)
        for source in ("deployment.example.json", "README.md"):
            shutil.copy(INSTALLER / source, bundle)
        if (PROJECT / "LICENSE").is_file():
            shutil.copy(PROJECT / "LICENSE", bundle)
        install_files = ["install.ps1", "run-probe.cmd"] if windows else ["install.sh"]
        if system == "linux":
            install_files.append("sbom-probe.service")
        elif system == "darwin":
            install_files.append("org.sbom-probe.agent.plist")
        for install_file in install_files:
            shutil.copy(INSTALLER / ("windows" if windows else "unix") / install_file, bundle)
        (bundle / "target.txt").write_text(f"{target}\n", encoding="utf-8")
        (bundle / "syft-version.txt").write_text(f"{SYFT_VERSION}\n", encoding="utf-8")
        return Path(shutil.make_archive(str(dist / name), "zip" if windows else "gztar", workspace, name))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="0.1.0", help="Versión semántica de la sonda")
    parser.add_argument("--target", action="append", choices=TARGETS, help="Repetible. Por defecto, los seis destinos")
    parser.add_argument("--cache-dir", type=Path, default=PROJECT / ".cache" / "syft")
    parser.add_argument("--dist-dir", type=Path, default=PROJECT / "dist")
    args = parser.parse_args()
    release = args.version.removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", release):
        parser.error("--version debe ser una versión semántica")
    cache = args.cache_dir.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    dist = args.dist_dir.resolve()
    dist.mkdir(parents=True, exist_ok=True)
    hashes = checksums(cache)
    packages = [build_package(target, release, hashes, cache, dist) for target in dict.fromkeys(args.target or TARGETS)]
    (dist / "SHA256SUMS").write_text(
        "".join(f"{sha256(package)}  {package.name}\n" for package in sorted(packages)),
        encoding="utf-8",
    )
    for package in packages:
        print(package)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"Error al empaquetar: {error}")
