"""Instala y reinstala la sonda en un runner desechable y recibe sus dos inventarios por mTLS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time
from urllib.request import Request, urlopen
from urllib.error import URLError
import uuid

WINDOWS = os.name == "nt"


def certificados(tmp):
    openssl = shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe"
    def ejecutar(*args):
        subprocess.run([openssl, *args], cwd=tmp, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ejecutar("req","-x509","-newkey","rsa:2048","-nodes","-subj","/CN=CI CA","-days","2",
             "-keyout","ca.key","-out","ca.crt","-addext","basicConstraints=critical,CA:TRUE")
    for nombre, uso in (("server","serverAuth"),("cliente","clientAuth")):
        ejecutar("req","-new","-newkey","rsa:2048","-nodes","-subj","/CN="+nombre,"-keyout",nombre+".key","-out",nombre+".csr")
        (tmp / "ext").write_text("extendedKeyUsage="+uso+"\nsubjectAltName=IP:127.0.0.1\n")
        ejecutar("x509","-req","-in",nombre+".csr","-CA","ca.crt","-CAkey","ca.key","-CAcreateserial",
                 "-days","2","-extfile","ext","-out",nombre+".crt")


def main(paquete, servidor, evidencia=None):
    paquete = str(paquete.resolve())
    token = secrets.token_hex(32)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp=Path(tmpdir)
        certificados(tmp)
        with socket.socket() as disponible:
            disponible.bind(("127.0.0.1", 0))
            puerto = disponible.getsockname()[1]
        origen = f"https://127.0.0.1:{puerto}"
        config = tmp/"monitor.json"
        config.write_text(json.dumps({"listen": f"127.0.0.1:{puerto}", "data_dir":str(tmp/"datos"),
                          "tls_cert":str(tmp/"server.crt"), "tls_key":str(tmp/"server.key"),
                          "client_ca":str(tmp/"ca.crt"), "admin_token":secrets.token_hex(32), "clients":{"acme":token}}))
        contexto = ssl.create_default_context(cafile=tmp/"ca.crt")
        contexto.load_cert_chain(tmp/"cliente.crt",tmp/"cliente.key")
        def leer(ruta):
            peticion = Request(origen+ruta, headers={"Authorization":"Bearer "+token})
            with urlopen(peticion,context=contexto,timeout=5) as respuesta:
                return respuesta.read()
        def recibir(vistos):
            plazo = time.monotonic()+120
            while time.monotonic()<plazo:
                for r in json.loads(leer("/v1/reports"))["items"]:
                    if r["report_id"] in vistos:
                        continue
                    rid = r["report_id"]
                    bruto = leer("/v1/reports/"+rid+"/sbom")
                    campos = ("schema_version","report_id","machine_id","client_id","collected_at","hostname","os","arch","source","metadata")
                    sobre = json.dumps({k:r[k] for k in campos},ensure_ascii=False,separators=(",",":"))
                    for literal,escape in (("&",r"\u0026"),("<",r"\u003c"),(">",r"\u003e"),("\u2028",r"\u2028"),("\u2029",r"\u2029")):
                        sobre=sobre.replace(literal,escape)
                    contenido=sobre[:-1].encode()+b',"sbom":'+bruto+b'}'
                    manifiesto=tmp/"datos/reports"/b"acme".hex()/rid/"manifest.json"
                    assert hashlib.sha256(contenido).hexdigest()==json.loads(manifiesto.read_bytes())["sha256"], "Difiere la carga original"
                    return json.loads(contenido),contenido
                time.sleep(1)
            raise TimeoutError("El recolector no recibió el inventario")
        perfil=tmp/"equipo.sbom"
        perfil.write_text(json.dumps({"version":1,"server_url":origen,
                        "client_id":"acme","metadata":{"group":"instaladores","tags":{"origen":"runner-ci"}},
                        "ca":(tmp/"ca.crt").read_text(),"certificate":(tmp/"cliente.crt").read_text(),
                        "key":(tmp/"cliente.key").read_text(),"token":token}))
        env={**os.environ, "SBOM_SETUP_QUIET":"1"}
        if WINDOWS:
            import winreg
            llave=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SBOM-Test-Ficticio"
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,llave) as k:
                winreg.SetValueEx(k,"DisplayName",0,winreg.REG_SZ,"Programa ficticio")
                winreg.SetValueEx(k,"DisplayVersion",0,winreg.REG_SZ,"2.3.4")
            orden=[paquete,"install",str(perfil)]
            esperado="Programa ficticio"
        else:
            subprocess.run(["sudo","dpkg","-i",paquete],check=True)
            orden=["sudo","sbom-probe-activar",str(perfil)]
            esperado="coreutils"
        monitor=subprocess.Popen([servidor, "-config", config])
        try:
            for i in range(40):
                try:
                    leer("/healthz")
                    break
                except URLError:
                    if monitor.poll() is not None: raise RuntimeError("El recolector terminó")
                    time.sleep(0.25)
            ids=[]
            for vez in (1,2):
                subprocess.run(orden,check=True,env=env,timeout=120)
                r, contenido=recibir({str(t[1]) for t in ids})
                assert r["os"] == ("windows" if WINDOWS else "linux") and r["arch"]=="amd64", r["os"]
                assert r["client_id"]=="acme" and r["metadata"]["group"]=="instaladores"
                assert r["sbom"]["bomFormat"]=="CycloneDX"
                componentes=r["sbom"]["components"]
                assert any(c["name"]==esperado for c in componentes), "Falta el paquete de control"
                ids.append((uuid.UUID(r["machine_id"]),uuid.UUID(r["report_id"])))
                print(f"Instalación {vez}: {r['os']} {r['arch']}, {len(componentes)} componentes, mTLS confirmado.",flush=True)
            assert ids[0][0]==ids[1][0] and ids[0][1]!=ids[1][1], "Identidad o repetición incorrecta"
            if evidencia:
                evidencia.write_bytes(contenido)
        finally:
            monitor.terminate()
            monitor.wait(timeout=40)
            if WINDOWS:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE,llave)
                subprocess.run([paquete,"uninstall"],env=env,check=True,timeout=60)
            else:
                subprocess.run(["sudo","dpkg","-r","sbom-probe"],check=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paquete",type=Path)
    parser.add_argument("--servidor",type=Path,required=True)
    parser.add_argument("--evidencia",type=Path)
    args=parser.parse_args()
    main(args.paquete,args.servidor.resolve(),args.evidencia)
