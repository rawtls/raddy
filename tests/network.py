from contextlib import ExitStack
from http.client import HTTPResponse
from pathlib import Path
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time


SIGNATURE = b"\r\n\r\n\0\r\nQUIT\n"


def allocate():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        assert chunk, (len(data), count)
        data.extend(chunk)
    return bytes(data)


def closed(sock):
    try:
        assert sock.recv(1) == b""
    except ConnectionResetError:
        pass


def main(binary):
    with ExitStack() as resources:
        root = Path(resources.enter_context(tempfile.TemporaryDirectory()))
        key, cert, config = (root / file for file in ("key.pem", "cert.pem", "Raddyfile"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=*.example.test", "-addext", "subjectAltName=DNS:*.example.test",
                        "-keyout", key, "-out", cert], check=True, capture_output=True)
        tls = ssl.create_default_context(cafile=str(cert))
        public = root / "public"
        public.mkdir()
        (public / "small.txt").write_bytes(b"abcdef")
        large = bytes(range(256)) * 1024
        (public / "large.bin").write_bytes(large)
        (public / "blocked").symlink_to(key)
        backend = resources.enter_context(socket.socket())
        backend.bind(("127.0.0.1", 0))
        backend.listen()
        backend.settimeout(3)
        http, shared, relay = (allocate() for _ in range(3))
        upstream = backend.getsockname()[1]

        def configure(limit, body, mode=""):
            config.write_text(f'''{{
    default_bind 127.0.0.1
    http_port {http}
    https_port {shared}
    max_connections {limit}
    proxy_protocol_accept {shared} {mode} 127.0.0.1/32
}}
https://identity.example.test {{
    tls {cert} {key}
    @forwarded expression `{{client_ip}} == "198.51.100.9"`
    @direct expression `{{client_ip}} == "127.0.0.2"`
    handle @forwarded {{ respond forwarded }}
    handle @direct {{ respond direct }}
    handle {{ respond unknown }}
}}
https://*.example.test {{
    tls {cert} {key}
    respond / "{body}"
    root {public}
    file_server
}}
tls://pass.example.test:{shared} {{
    proxy 127.0.0.1:{upstream} {{
        proxy_protocol v2
    }}
}}
tcp://:{shared} {{
    proxy 127.0.0.1:{upstream}
}}
tcp://:{relay} {{
    proxy 127.0.0.1:{upstream} {{
        proxy_protocol v1
    }}
}}
''')

        configure(2, "old")
        log = resources.enter_context((root / "raddy.log").open("w+"))
        subprocess.run([binary, "--config", config, "validate"], check=True, capture_output=True)
        process = subprocess.Popen([binary, "--config", config, "run", "--grace-period-secs", "1"], stdout=log, stderr=subprocess.STDOUT)

        def stop():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        resources.callback(stop)

        def wait(message):
            deadline = time.monotonic() + 5
            while message not in re.sub(r"\x1b\[[0-9;]*m", "", (root / "raddy.log").read_text()):
                if process.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError((message, (root / "raddy.log").read_text()))
                time.sleep(0.03)

        def connect(port, proxy=False):
            conn = socket.create_connection(("127.0.0.1", port), 3)
            if proxy:
                conn.sendall(b"PROXY TCP4 198.51.100.9 203.0.113.6 5678 443\r\n")
            return conn

        def https(expected):
            with connect(shared, proxy=True) as conn, tls.wrap_socket(conn, server_hostname="web.example.test") as client:
                client.sendall(b"GET / HTTP/1.1\r\nHost: web.example.test\r\nConnection: close\r\n\r\n")
                data = bytearray()
                while chunk := client.recv(4096):
                    data.extend(chunk)
                assert data.startswith(b"HTTP/1.1 200 ") and data.endswith(expected), data

        wait(f"address=127.0.0.1:{shared}")
        https(b"old")
        with connect(shared, proxy=True) as conn, tls.wrap_socket(conn, server_hostname="web.example.test") as client:
            def request(method, path, headers=""):
                client.sendall(f"{method} {path} HTTP/1.1\r\nHost: web.example.test\r\n{headers}\r\n".encode())
                with HTTPResponse(client, method=method) as response:
                    response.begin()
                    return response.status, response.headers, response.read()

            status, headers, body = request("GET", "/small.txt")
            assert (status, body) == (200, b"abcdef")
            tag = headers["ETag"]
            assert tag
            status, headers, body = request("HEAD", "/small.txt")
            assert (status, headers["ETag"], headers["Content-Length"], body) == (200, tag, "6", b"")
            status, _, body = request("GET", "/small.txt", f"If-None-Match: {tag}\r\n")
            assert (status, body) == (304, b"")
            status, headers, body = request("GET", "/small.txt", f"Range: bytes=1-3\r\nIf-Range: {tag}\r\n")
            assert (status, headers["Content-Range"], body) == (206, "bytes 1-3/6", b"bcd")
            status, _, body = request("GET", "/large.bin")
            assert (status, body) == (200, large)
            status, headers, body = request("GET", "/large.bin", "Range: bytes=8193-8255\r\n")
            assert (status, headers["Content-Range"], body) == (206, f"bytes 8193-8255/{len(large)}", large[8193:8256])
            status, _, _ = request("GET", "/blocked")
            assert status == 403
        with connect(shared, proxy=True) as conn:
            conn.sendall(b"raw")
            with backend.accept()[0] as upstream_conn:
                assert exact(upstream_conn, 3) == b"raw"
        with connect(relay) as conn, backend.accept()[0] as upstream_conn:
            upstream_conn.settimeout(3)
            fields = bytearray()
            while not fields.endswith(b"\r\n"):
                fields.extend(exact(upstream_conn, 1))
            assert fields == f"PROXY TCP4 127.0.0.1 127.0.0.1 {conn.getsockname()[1]} {relay}\r\n".encode()
        with connect(shared, proxy=True) as conn:
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            client = tls.wrap_bio(incoming, outgoing, server_hostname="pass.example.test")
            try:
                client.do_handshake()
            except ssl.SSLWantReadError:
                pass
            hello = outgoing.read()
            conn.sendall(hello[:2])
            conn.sendall(hello[2:])
            with backend.accept()[0] as upstream_conn:
                upstream_conn.settimeout(3)
                assert exact(upstream_conn, 16) == SIGNATURE + b"\x21\x11\x00\x0c"
                expected = socket.inet_aton("198.51.100.9") + socket.inet_aton("203.0.113.6") + struct.pack("!HH", 5678, 443)
                assert exact(upstream_conn, 12) == expected
                assert exact(upstream_conn, len(hello)) == hello
                conn.shutdown(socket.SHUT_WR)
                closed(upstream_conn)
                upstream_conn.shutdown(socket.SHUT_WR)
                closed(conn)

        def relay_pair():
            client = resources.enter_context(connect(relay))
            endpoint = resources.enter_context(backend.accept()[0])
            endpoint.settimeout(3)
            preface = f"PROXY TCP4 127.0.0.1 127.0.0.1 {client.getsockname()[1]} {relay}\r\n".encode()
            assert exact(endpoint, len(preface)) == preface
            return client, endpoint

        first, first_up = relay_pair()
        second, second_up = relay_pair()
        with connect(shared) as excess:
            closed(excess)
        configure(1, "new")
        process.send_signal(signal.SIGUSR1)
        wait("configuration reloaded")
        first_up.sendall(b"still open")
        assert exact(first, 10) == b"still open"
        with connect(shared) as excess:
            closed(excess)
        first.shutdown(socket.SHUT_WR)
        second.shutdown(socket.SHUT_WR)
        first_up.shutdown(socket.SHUT_WR)
        second_up.shutdown(socket.SHUT_WR)
        closed(first)
        closed(second)
        deadline = time.monotonic() + 3
        while True:
            try:
                https(b"new")
                break
            except (ConnectionResetError, ssl.SSLEOFError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
        def identity(source, preface=b""):
            with socket.create_connection(("127.0.0.1", shared), 3, (source, 0)) as conn:
                if preface:
                    conn.sendall(preface)
                with tls.wrap_socket(conn, server_hostname="identity.example.test") as client:
                    client.sendall(b"GET / HTTP/1.1\r\nHost: identity.example.test\r\nX-Forwarded-For: 198.51.100.9\r\nConnection: close\r\n\r\n")
                    with HTTPResponse(client) as response:
                        response.begin()
                        assert response.status == 200
                        return response.read()

        def rejected(source, preface=b""):
            try:
                identity(source, preface)
            except (ssl.SSLError, ConnectionError):
                return
            raise AssertionError("unexpectedly accepted " + source)

        v1 = b"PROXY TCP4 198.51.100.9 203.0.113.6 5678 443\r\n"
        v2 = SIGNATURE + b"\x21\x11\x00\x0c" + expected
        rejected("127.0.0.2", v1)
        configure(32, "mixed", "from_trusted")
        process.send_signal(signal.SIGUSR1)
        deadline = time.monotonic() + 5
        while True:
            try:
                https(b"mixed")
                break
            except (AssertionError, ConnectionError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.03)
        assert identity("127.0.0.2") == b"direct"
        for preface in (v1, v2):
            assert identity("127.0.0.1", preface) == b"forwarded"
            rejected("127.0.0.2", preface)
        rejected("127.0.0.1")
        rejected("127.0.0.1", b"PROXY broken\r\n")
        with socket.create_connection(("127.0.0.1", shared), 3, ("127.0.0.2", 0)) as conn:
            conn.sendall(hello)
            with backend.accept()[0] as upstream_conn:
                upstream_conn.settimeout(3)
                assert exact(upstream_conn, 16) == SIGNATURE + b"\x21\x11\x00\x0c"
                assert exact(upstream_conn, 12) == socket.inet_aton("127.0.0.2") + socket.inet_aton("127.0.0.1") + struct.pack("!HH", conn.getsockname()[1], shared)
                assert exact(upstream_conn, len(hello)) == hello
        assert process.poll() is None
        print("Shared port, strict/mixed PROXY v1/v2, TLS static files, connection admission and reload passed")


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve()))
