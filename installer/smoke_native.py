"""Instala y reinstala la sonda en un runner desechable y recibe sus dos inventarios por mTLS."""
import argparse
import http.server
import json
import os
from pathlib import Path
import queue
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
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


def main(paquete):
    paquete = str(paquete.resolve())
    recibidos = queue.Queue()
    token = secrets.token_hex(32)
    class Recibir(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/v1/reports" or self.headers.get("Authorization") != "Bearer " + token:
                self.send_error(403)
                return
            reporte = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(201)
            self.end_headers()
            recibidos.put(reporte)
        def log_message(self,*args):
            pass

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp=Path(tmpdir)
        certificados(tmp)
        server=http.server.ThreadingHTTPServer(("127.0.0.1",0), Recibir)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tmp/"server.crt",tmp/"server.key")
        ctx.load_verify_locations(tmp/"ca.crt")
        ctx.verify_mode=ssl.CERT_REQUIRED
        server.socket=ctx.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        perfil=tmp/"equipo.sbom"
        perfil.write_text(json.dumps({"version":1,"server_url":f"https://127.0.0.1:{server.server_port}",
                        "client_id":"laboratorio","metadata":{"group":"instaladores"},
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
        try:
            ids=[]
            for vez in (1,2):
                subprocess.run(orden,check=True,env=env,timeout=120)
                r=recibidos.get(timeout=120)
                assert r["os"] == ("windows" if WINDOWS else "linux") and r["arch"]=="amd64", r["os"]
                assert r["client_id"]=="laboratorio" and r["metadata"]["group"]=="instaladores"
                assert r["sbom"]["bomFormat"]=="CycloneDX"
                componentes=r["sbom"]["components"]
                assert any(c["name"]==esperado for c in componentes), "Falta el paquete de control"
                ids.append((uuid.UUID(r["machine_id"]),uuid.UUID(r["report_id"])))
                print(f"Instalación {vez}: {r['os']} {r['arch']}, {len(componentes)} componentes, mTLS confirmado.",flush=True)
            assert ids[0][0]==ids[1][0] and ids[0][1]!=ids[1][1], "Identidad o repetición incorrecta"
        finally:
            server.shutdown()
            server.server_close()
            if WINDOWS:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE,llave)
                subprocess.run([paquete,"uninstall"],env=env,check=True,timeout=60)
            else:
                subprocess.run(["sudo","dpkg","-r","sbom-probe"],check=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paquete",type=Path)
    main(parser.parse_args().paquete)
