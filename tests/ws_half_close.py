import socket
import ssl
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from benchmark import distinct_ports, stop


REQUEST = (b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
           b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
           b"Sec-WebSocket-Version: 13\r\n\r\n")
REPLY = (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
         b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")


def header(sock):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        chunk = sock.recv(1024)
        assert chunk and len(data) < 8192, data
        data.extend(chunk)
    return data


def main(binary):
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        backend = stack.enter_context(socket.socket())
        backend.bind(("127.0.0.1", 0))
        backend.listen()
        backend.settimeout(3)
        origin = backend.getsockname()[1]
        http, https = distinct_ports(origin)
        subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "ec",
                        "-pkeyopt", "ec_paramgen_curve:P-256", "-days", "1", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost", "-keyout", "key.pem", "-out", "cert.pem"],
                       cwd=root, check=True, capture_output=True)
        ctx = ssl.create_default_context(cafile=str(root / "cert.pem"))
        route = f"reverse_proxy 127.0.0.1:{origin} {{ proxy_protocol v2 }}"
        (root / "Raddyfile").write_text(f"{{\n default_bind 127.0.0.1\n http_port {http}\n https_port {https}\n}}\n"
                                       f"http://localhost {{\n {route}\n}}\n"
                                       f"https://localhost {{\n tls cert.pem key.pem\n {route}\n}}\n")
        proc = subprocess.Popen([binary, "run", "--grace-period-secs", "0"], cwd=root)
        stack.callback(stop, proc)

        def connect(scope, tls):
            sock = scope.enter_context(socket.create_connection(("127.0.0.1", https if tls else http), 3))
            if tls:
                sock = scope.enter_context(ctx.wrap_socket(sock, server_hostname="localhost"))
            sock.sendall(REQUEST)
            peer = scope.enter_context(backend.accept()[0])
            peer.settimeout(3)
            assert peer.recv(28, socket.MSG_WAITALL).startswith(b"\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c")
            assert header(peer).startswith(b"GET /ws ")
            peer.sendall(REPLY)
            assert header(sock).startswith(b"HTTP/1.1 101 ")
            return sock, peer

        for i in range(100):
            try:
                with socket.create_connection(("127.0.0.1", http), 0.2):
                    break
            except OSError:
                if proc.poll() is not None or i == 99:
                    raise
                time.sleep(0.05)
        live, live_peer = connect(stack, True)
        fd_dir = Path(f"/proc/{proc.pid}/fd")
        baseline = len(list(fd_dir.iterdir()))
        for _ in range(2):
            with ExitStack() as held:
                for i in range(24):
                    tls = i % 3 == 0
                    client, origin_sock = connect(held, tls)
                    first, other = (client, origin_sock) if i % 3 == 1 else (origin_sock, client)
                    first.shutdown(socket.SHUT_WR)
                    assert other.recv(1) == b""
                    if not tls:
                        other.sendall(b"tail")
                        assert first.recv(4, socket.MSG_WAITALL) == b"tail"
                deadline = time.monotonic() + 14
                while (fds := len(list(fd_dir.iterdir()))) > baseline and time.monotonic() < deadline:
                    time.sleep(0.1)
                assert fds <= baseline, f"half-closed peers held open: {fds} process FDs vs baseline {baseline}"
            live.sendall(b"\x82\x81\x01\x02\x03\x04\x60")
            assert live_peer.recv(7, socket.MSG_WAITALL) == b"\x82\x81\x01\x02\x03\x04\x60"
            live_peer.sendall(b"\x82\x01a")
            assert live.recv(3) == b"\x82\x01a"
        print(f"Two waves of half-closed WebSockets released (baseline {baseline} FDs); idle WSS survived")


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve()))
