"""Produce los instaladores sin red. Requiere Go y LLVM para el manifiesto UAC de Windows."""
import argparse
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
UNIT = (ROOT / "installer/unix/sbom-probe.service").read_bytes()
ACTIVAR = b"""#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo "Use sudo." >&2; exit 1; }
[ "$#" = 1 ] || { echo "Uso: sudo sbom-probe-activar equipo.sbom" >&2; exit 2; }
umask 077
install -m 0700 -d /etc/sbom-probe
/opt/sbom-probe/sbom-probe enroll -profile "$1" -config /etc/sbom-probe/config.json
systemctl daemon-reload
systemctl enable sbom-probe.service
systemctl restart sbom-probe.service
systemctl is-active sbom-probe.service
"""
POSTINST = b"""#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
 systemctl daemon-reload
 if [ -f /etc/sbom-probe/config.json ]; then systemctl restart sbom-probe.service; fi
fi
"""
PRERM = b"""#!/bin/sh
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then systemctl disable --now sbom-probe.service; fi
"""
MANIFEST = '''<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<assemblyIdentity name="SBOM.Probe.Setup" version="1.0.0.0" type="win32"/>
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>
<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
</requestedPrivileges></security></trustInfo></assembly>'''


def tar(entries):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as archive:
        directories = {parent for name, _, _ in entries for parent in PurePosixPath(name).parents if str(parent) != "."}
        for parent in sorted(directories, key=lambda x: (len(x.parts), str(x))):
            item = tarfile.TarInfo("./" + str(parent) + "/")
            item.type, item.mode = tarfile.DIRTYPE, 0o755
            item.uname = item.gname = "root"
            archive.addfile(item)
        for name, mode, contents in entries:
            item = tarfile.TarInfo("./" + name)
            item.size, item.mode = len(contents), mode
            item.uname = item.gname = "root"
            archive.addfile(item, io.BytesIO(contents))
    return result.getvalue()


def deb(destination, exe, arch, version):
    control = f"""Package: sbom-probe
Version: {version}
Architecture: {arch}
Maintainer: SBOM Monitor <soporte@localhost>
Depends: systemd
Section: admin
Priority: optional
Description: Sonda de inventario CycloneDX para el monitor SBOM
"""
    control_tar = tar([("control", 0o644, control.encode()), ("postinst", 0o755, POSTINST), ("prerm", 0o755, PRERM)])
    data_tar = tar([("opt/sbom-probe/sbom-probe", 0o755, exe.read_bytes()),
                    ("usr/sbin/sbom-probe-activar", 0o755, ACTIVAR),
                    ("lib/systemd/system/sbom-probe.service", 0o644, UNIT)])
    with destination.open("wb") as out:
        out.write(b"!<arch>\n")
        for name, data in [("debian-binary", b"2.0\n"), ("control.tar.gz", control_tar), ("data.tar.gz", data_tar)]:
            out.write(f"{name+'/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode() + data)
            if len(data) % 2:
                out.write(b"\n")


def build(target, version, dist):
    system, arch = target.split("_")
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": system, "GOARCH": arch}
    with tempfile.TemporaryDirectory(prefix="sonda-build-") as folder:
        work = Path(folder)
        project = ROOT
        if system == "windows":
            project = work / "src"
            shutil.copytree(ROOT / "cmd", project / "cmd")
            shutil.copy(ROOT / "go.mod", project)
            (work / "setup.manifest").write_text(MANIFEST, encoding="utf-8")
            (work / "setup.rc").write_text('1 24 "setup.manifest"\n', encoding="ascii")
            subprocess.run(["llvm-rc", "/fo", "setup.res", "setup.rc"], cwd=work, check=True)
            obj = project / "cmd/sbom-probe" / f"admin_windows_{arch}.syso"
            machine = {"amd64": "X64", "arm64": "ARM64"}[arch]
            subprocess.run(["llvm-cvtres", f"/machine:{machine}", f"/out:{obj}", "setup.res"], cwd=work, check=True)
        binary = work / "probe"
        subprocess.run(["go", "build", "-trimpath", "-ldflags", f"-s -w -X main.version={version}",
                        "-o", binary, "./cmd/sbom-probe"], cwd=project, check=True, env=env)
        if system == "windows":
            path = dist / f"sbom-probe-setup-{version}-windows-{arch}.exe"
            shutil.copyfile(binary, path)
        else:
            path = dist / f"sbom-probe_{version}_{arch}.deb"
            deb(path, binary, arch, version)
        return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist/native")
    parser.add_argument("--target", action="append", choices=["linux_amd64", "linux_arm64", "windows_amd64", "windows_arm64"])
    args = parser.parse_args()
    args.dist.mkdir(parents=True, exist_ok=True)
    version = (ROOT / "VERSION").read_text().strip()
    packages = [build(target, version, args.dist) for target in dict.fromkeys(args.target or
                ("linux_amd64", "linux_arm64", "windows_amd64", "windows_arm64"))]
    with (args.dist / "SHA256SUMS").open("w") as sums:
        for path in packages:
            sums.write(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
            print(path)
