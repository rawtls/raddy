import http.client
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from benchmark import distinct_ports, stop


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        data = self.rfile.read(int(self.headers["Content-Length"]))
        try:
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main(binary):
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        backend = stack.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), Origin))
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        stack.callback(backend.shutdown)
        config = root / "Raddyfile"
        port, tls_port = distinct_ports(backend.server_port)
        config.write_text(f'''{{
    default_bind 127.0.0.1
    http_port {port}
    https_port {tls_port}
    request_timeout 1s
}}
http://localhost:{port} {{
    handle /upload {{
        reverse_proxy 127.0.0.1:{backend.server_port}
    }}
    handle {{
        respond ok
    }}
}}
''')
        log = stack.enter_context((root / "raddy.log").open("w+"))
        process = subprocess.Popen([binary, "--config", config, "run", "--grace-period-secs", "0"],
                                   cwd=root, stdout=log, stderr=subprocess.STDOUT)
        stack.callback(stop, process)
        for attempt in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                if process.poll() is not None or attempt == 99:
                    log.seek(0)
                    raise AssertionError(log.read())
                time.sleep(0.03)
        for target, headers in [(f"http://localhost:{port}/", {}), ("/", {f"X-Test-{i}": "ok" for i in range(70)})]:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
            try:
                conn.request("GET", target, headers={"Host": f"localhost:{port}", **headers})
                reply = conn.getresponse()
                assert (reply.status, reply.read()) == (200, b"ok"), target
            finally:
                conn.close()
        for active in (True, False):
            with socket.create_connection(("127.0.0.1", port), 4) as conn:
                conn.sendall(b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\nConnection: close\r\n\r\n")
                if active:
                    for byte in b"streamed":
                        conn.sendall(bytes([byte]))
                        time.sleep(0.2)
                else:
                    conn.sendall(b"s")
                with http.client.HTTPResponse(conn) as reply:
                    reply.begin()
                    expected = (200, b"streamed") if active else (504, b"upstream request timed out\n")
                    assert (reply.status, reply.read()) == expected, (active, reply.status)
        invalid = root / "invalid.Raddyfile"
        invalid.write_text(f"http://localhost:{port} {{\n root {root / 'missing'}\n file_server\n}}\n")
        result = subprocess.run([binary, "--config", invalid, "validate"], cwd=root, capture_output=True, timeout=5)
        assert result.returncode != 0 and b"No such file" in result.stderr, result.stderr
        print("HTTP parser fallback, upload progress and idle timeout, and validation passed")


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve()))
