from http.client import HTTPResponse
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from benchmark import stop


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main(binary):
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))

        def origin():
            obj = stack.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), Origin))
            return obj

        def serve(obj):
            threading.Thread(target=obj.serve_forever, daemon=True).start()
            stack.callback(obj.shutdown)

        files, backend = origin(), origin()
        serve(files)

        def cert(name, san):
            pem, key = root / (name + ".pem"), root / (name + ".key")
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-nodes",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=" + name,
                    "-addext",
                    "subjectAltName=" + san,
                    "-keyout",
                    key,
                    "-out",
                    pem,
                ],
                check=True,
                capture_output=True,
            )
            return pem, key

        public_cert = cert("public", "DNS:*.multi.test,DNS:outside.test")
        local_cert = cert("local", "DNS:*.multi.test,DNS:inside.test")
        pass_cert = cert("pass", "DNS:pass.multi.test")
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(*pass_cert)
        backend.socket = tls.wrap_socket(backend.socket, server_side=True)
        serve(backend)
        trust = ssl.create_default_context()
        for pem, _ in (public_cert, local_cert, pass_cert):
            trust.load_verify_locations(pem)
        with ExitStack() as reserved:
            ports = []
            for _ in range(3):
                sock = reserved.enter_context(socket.socket())
                sock.bind(("127.0.0.1", 0))
                ports.append(sock.getsockname()[1])
        http, public, local = ports
        cfg = root / "Raddyfile"

        def configure(generation, include_local):
            shared = f"""tls://pass.multi.test:{public} {{
 proxy 127.0.0.1:{backend.server_port}
}}
*.multi.test, outside.test {{
 tls {public_cert[0]} {public_cert[1]}
 handle /tunnel/* {{
  reverse_proxy http://127.0.0.1:{files.server_port}
 }}
 handle {{
  respond {generation}
 }}
}}
"""
            private = f"""https://*.multi.test:{local}, https://inside.test:{local} {{
 bind 127.0.0.1
 tls {local_cert[0]} {local_cert[1]}
 handle {{
  rewrite /private/
  reverse_proxy http://127.0.0.1:{files.server_port}
 }}
}}
"""
            cfg.write_text(
                f"{{\n default_bind 127.0.0.2\n http_port {http}\n https_port {public}\n}}\n"
                + (private if include_local else "")
                + shared
            )

        def request(ip, port, sni, path="/tunnel/file", host=None):
            with (
                socket.create_connection((ip, port), 2) as raw,
                trust.wrap_socket(raw, server_hostname=sni) as conn,
            ):
                conn.sendall(
                    f"GET {path} HTTP/1.1\r\nHost: {host or sni}\r\nConnection: close\r\n\r\n".encode()
                )
                with HTTPResponse(conn) as resp:
                    resp.begin()
                    return resp.status, resp.read(), conn.getpeercert(binary_form=True)

        def check(ip, port, sni, pem, expected, path="/tunnel/file"):
            status, body, cert_der = request(ip, port, sni, path)
            assert (status, body, cert_der) == (
                200,
                expected,
                ssl.PEM_cert_to_DER_cert(pem.read_text()),
            ), (status, body, sni)

        configure("one", True)
        subprocess.run(
            [binary, "--config", cfg, "validate"], check=True, capture_output=True
        )
        log = stack.enter_context((root / "server.log").open("w+"))
        proc = subprocess.Popen(
            [binary, "--config", cfg, "run", "--grace-period-secs", "0"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        stack.callback(stop, proc)

        def wait_for(fn):
            end = time.monotonic() + 5
            while True:
                try:
                    fn()
                    return
                except (OSError, AssertionError):
                    if proc.poll() is not None or time.monotonic() > end:
                        log.seek(0)
                        print(log.read(), file=sys.stderr)
                        raise
                    time.sleep(0.04)

        wait_for(
            lambda: check(
                "127.0.0.2", public, "app.multi.test", public_cert[0], b"one", "/"
            )
        )
        check("127.0.0.2", public, "app.multi.test", public_cert[0], b"/tunnel/file")
        check("127.0.0.2", public, "pass.multi.test", pass_cert[0], b"/tunnel/file")
        check("127.0.0.1", local, "pass.multi.test", local_cert[0], b"/private/")
        for ip, port, sni, other in [
            ("127.0.0.2", public, "outside.test", "inside.test"),
            ("127.0.0.1", local, "inside.test", "outside.test"),
        ]:
            assert request(ip, port, sni, host=other)[0] == 404
            try:
                request(ip, port, other)
            except ssl.SSLError:
                pass
            else:
                raise AssertionError("other listener accepted SNI " + other)
        with socket.create_connection(("127.0.0.2", http), 2) as conn:
            conn.sendall(
                b"GET /a?b=1 HTTP/1.1\r\nHost: app.multi.test\r\nConnection: close\r\n\r\n"
            )
            with HTTPResponse(conn) as resp:
                resp.begin()
                assert (resp.status, resp.getheader("Location")) == (
                    308,
                    f"https://app.multi.test:{public}/a?b=1",
                )
        configure("two", False)
        os.kill(proc.pid, signal.SIGUSR1)
        wait_for(
            lambda: check(
                "127.0.0.2", public, "app.multi.test", public_cert[0], b"two", "/"
            )
        )

        def removed():
            try:
                with socket.create_connection(("127.0.0.1", local), 1):
                    pass
            except ConnectionRefusedError:
                return
            raise AssertionError("removed listener still active")

        wait_for(removed)
        configure("three", True)
        os.kill(proc.pid, signal.SIGUSR1)
        wait_for(
            lambda: check(
                "127.0.0.1", local, "app.multi.test", local_cert[0], b"/private/"
            )
        )
        check("127.0.0.2", public, "pass.multi.test", pass_cert[0], b"/tunnel/file")
        cfg.write_text(
            f"""{{
 default_bind 127.0.0.1
 http_port {http}
 https_port {public}
}}
https://*.multi.test:{local},
https://outside.test,
other.multi.test {{
 tls {public_cert[0]} {public_cert[1]}
 respond shared
}}
"""
        )
        os.kill(proc.pid, signal.SIGUSR1)
        wait_for(lambda: check("127.0.0.1", local, "app.multi.test", public_cert[0], b"shared"))
        for sni in ("outside.test", "other.multi.test"):
            check("127.0.0.1", public, sni, public_cert[0], b"shared")
        print(
            "Independent HTTPS routes, certificates, SNI passthrough, redirects, reload and multiline site addresses passed"
        )


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve()))
