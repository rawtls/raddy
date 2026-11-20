import argparse
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Backend(ThreadingHTTPServer):
    request_queue_size = 256

    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
            super().handle_error(request, client_address)

    def process_request_thread(self, request, address):
        if self.proxy:
            data = bytearray()
            try:
                while not data.endswith(b"\r\n") and len(data) < 107:
                    chunk = request.recv(1)
                    if not chunk:
                        break
                    data.extend(chunk)
                if not data.startswith(b"PROXY ") or not data.endswith(b"\r\n"):
                    self.shutdown_request(request)
                    return
            except OSError:
                self.shutdown_request(request)
                return
        super().process_request_thread(request, address)


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    wbufsize = 4096

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def nginx_workers(pid):
    children = Path(f"/proc/{pid}/task/{pid}/children")
    return [int(child) for child in children.read_text().split()]


def sample(pids):
    cpu, rss = 0, 0
    for pid in pids:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        cpu += int(fields[11]) + int(fields[12])
        rss += int(fields[21]) * os.sysconf("SC_PAGE_SIZE")
    return cpu, rss


def nginx_config(root, plain, secure, backend):
    return f'''
worker_processes 1;
error_log stderr error;
pid {root}/nginx.pid;
events {{ worker_connections 4096; }}
http {{
    access_log off;
    sendfile on;
    tcp_nodelay on;
    keepalive_requests 100000;
    client_body_temp_path {root}/client;
    proxy_temp_path {root}/proxy;
    fastcgi_temp_path {root}/fastcgi;
    uwsgi_temp_path {root}/uwsgi;
    scgi_temp_path {root}/scgi;
    upstream echo {{ server 127.0.0.1:{backend}; keepalive 128; }}
    server {{
        listen 127.0.0.1:{plain};
        root {root}/public;
    }}
    server {{
        listen 127.0.0.1:{secure} ssl;
        ssl_certificate {root}/cert.pem;
        ssl_certificate_key {root}/key.pem;
        ssl_protocols TLSv1.3;
        ssl_session_tickets off;
        ssl_session_cache off;
        root {root}/public;
        location /proxy {{
            proxy_pass http://echo;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
            proxy_request_buffering off;
        }}
    }}
}}
'''


def caddy_config(root, plain, secure, backend):
    return f'''
{{
    admin off
    persist_config off
    auto_https disable_redirects
    servers {{
        protocols h1
    }}
}}
http://localhost:{plain} {{
    bind 127.0.0.1
    root {root}/public
    file_server
}}
https://localhost:{secure} {{
    bind 127.0.0.1
    tls {root}/cert.pem {root}/key.pem {{
        protocols tls1.3
    }}
    handle /proxy {{
        reverse_proxy http://127.0.0.1:{backend} {{
            flush_interval -1
            transport http {{
                versions 1.1
            }}
        }}
    }}
    handle {{
        root {root}/public
        file_server
    }}
}}
'''


def raddy_config(root, plain, secure, backend, proxy_backend):
    return f'''
{{
    default_bind 127.0.0.1
    http_port {plain}
    https_port {secure}
    auto_https disable_redirects
}}
:{plain} {{
    root {root}/public
    file_server
}}
https://localhost {{
    tls {root}/cert.pem {root}/key.pem
    handle /proxy {{
        reverse_proxy http://127.0.0.1:{backend}
    }}
    handle /proxy-pp {{
        reverse_proxy http://127.0.0.1:{proxy_backend} {{
            proxy_protocol v1
        }}
    }}
    handle {{
        root {root}/public
        file_server
    }}
}}
'''


def layer4_command(implementation, binary, root, plain, secure, backend, secure_backend, stream_module):
    if implementation == "nginx":
        cfg = root / "stream.conf"
        cfg.write_text(f'''load_module "{stream_module}";
worker_processes 1;
error_log stderr error;
pid {root}/stream.pid;
events {{ worker_connections 4096; }}
stream {{
    map $ssl_preread_server_name $target {{
        localhost 127.0.0.1:{secure_backend};
        default "";
    }}
    server {{
        listen 127.0.0.1:{plain};
        proxy_pass 127.0.0.1:{backend};
    }}
    server {{
        listen 127.0.0.1:{secure};
        ssl_preread on;
        proxy_pass $target;
    }}
}}
''')
        return [binary, "-p", str(root), "-c", str(cfg), "-g", "daemon off;"]
    if implementation == "caddy":
        cfg = root / "layer4.json"

        def route(port):
            return {"handle": [{"handler": "proxy", "upstreams": [{"dial": [f"127.0.0.1:{port}"]}]}]}

        secure_route = route(secure_backend)
        secure_route["match"] = [{"tls": {"sni": ["localhost"]}}]
        cfg.write_text(json.dumps({"admin": {"disabled": True, "config": {"persist": False}},
                                   "apps": {"layer4": {"servers": {
                                       "tcp": {"listen": [f"127.0.0.1:{plain}"], "routes": [route(backend)]},
                                       "tls": {"listen": [f"127.0.0.1:{secure}"], "routes": [secure_route]},
                                   }}}}))
        return [binary, "run", "--config", str(cfg)]
    cfg = root / "Layer4.Raddyfile"
    cfg.write_text(f'''tcp://127.0.0.1:{plain} {{
    proxy 127.0.0.1:{backend}
}}
tls://localhost:{secure} {{
    bind 127.0.0.1
    proxy 127.0.0.1:{secure_backend}
}}
''')
    return [binary, "--config", str(cfg), "run", "--grace-period-secs", "0"]


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def distinct_ports(*excluded):
    while True:
        first, second = port(), port()
        if first != second and first not in excluded and second not in excluded:
            return first, second


def main(args):
    if not sys_is_linux():
        raise SystemExit("This benchmark uses Linux /proc and CPU affinity")
    with ExitStack() as stack:
        cpus = sorted(os.sched_getaffinity(0))
        if len(cpus) < 3:
            raise SystemExit("At least three CPUs are needed to isolate server, generator and backend")
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="raddy-bench-")))
        os.sched_setaffinity(0, {cpus[2]})
        root.joinpath("public").mkdir()
        root.joinpath("public/sample").write_bytes(b"r" * 1024)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-keyout", root / "key.pem", "-out", root / "cert.pem"], check=True, capture_output=True)
        for file, connection, post in (("keep", False, False), ("new", True, False), ("post", False, True)):
            setup = 'wrk.headers["Connection"] = "close"\n' if connection else ""
            if post:
                setup += 'wrk.method = "POST"\nwrk.body = string.rep("a", 1024)\n'
            root.joinpath(f"{file}.lua").write_text(setup + '''
done = function(summary, latency, requests)
  io.write(string.format("RESULT %d %.0f %.0f %d %d %d %d %d\\n", summary.requests,
    latency:percentile(95.0), latency:percentile(99.0), summary.errors.connect,
    summary.errors.read, summary.errors.write, summary.errors.status, summary.errors.timeout))
end
''')
        backends = []
        for proxy in (False, True):
            server = Backend(("127.0.0.1", 0), Echo)
            server.proxy = proxy
            stack.callback(server.server_close)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            stack.callback(server.shutdown)
            backends.append(server.server_address[1])
        if args.layer4:
            tcp_backend, tls_backend = distinct_ports(*backends)
            cfg = root / "backend.conf"
            cfg.write_text(nginx_config(root, tcp_backend, tls_backend, backends[0]))
            log = stack.enter_context((root / "backend.log").open("w+"))
            process = subprocess.Popen(["taskset", "-c", str(cpus[2]), args.nginx, "-p", str(root),
                                        "-c", str(cfg), "-g", "daemon off;"], stdout=log, stderr=subprocess.STDOUT)
            stack.callback(stop, process)
            wait_ready(process, tls_backend, log, root / "cert.pem")
        versions = {"raddy": subprocess.check_output([args.raddy, "--version"], text=True).strip(),
                    "nginx": subprocess.run([args.nginx, "-v"], capture_output=True, text=True, check=True).stderr.strip()}
        if args.caddy:
            versions["caddy"] = subprocess.check_output([args.caddy, "version"], text=True).strip()
        if args.baseline:
            versions["raddy-baseline"] = subprocess.check_output([args.baseline, "--version"], text=True).strip()
        print(json.dumps({**versions,
                          "kernel": os.uname().release, "machine": os.uname().machine,
                          "available_cpus": len(cpus), "server_cpus": 1, "generator_cpus": 1,
                          "backend_cpu": cpus[2], "seconds": args.seconds, "connections": args.connections,
                          "runs": args.runs, "mode": "layer4" if args.layer4 else "http"}), flush=True)
        implementations = [("nginx", args.nginx), ("raddy", args.raddy)]
        if args.caddy:
            implementations.insert(0, ("caddy", args.caddy))
        if args.baseline:
            implementations.insert(-1, ("raddy-baseline", args.baseline))
        occupied = backends + ([tcp_backend, tls_backend] if args.layer4 else [])
        for implementation, binary in implementations:
            plain, secure = distinct_ports(*occupied)
            if args.layer4:
                cmd = layer4_command(implementation, binary, root, plain, secure, tcp_backend,
                                     tls_backend, args.nginx_stream_module)
            elif implementation == "nginx":
                cfg = root / "nginx.conf"
                cfg.write_text(nginx_config(root, plain, secure, backends[0]))
                cmd = [binary, "-p", str(root), "-c", str(cfg), "-g", "daemon off;"]
            elif implementation == "caddy":
                cfg = root / "Caddyfile"
                cfg.write_text(caddy_config(root, plain, secure, backends[0]))
                cmd = [binary, "run", "--config", str(cfg)]
            else:
                cfg = root / "Raddyfile"
                cfg.write_text(raddy_config(root, plain, secure, *backends))
                cmd = [binary, "--config", str(cfg), "run", "--grace-period-secs", "0"]
            with (root / f"{implementation}.log").open("w+") as log:
                process = subprocess.Popen(["taskset", "-c", str(cpus[0]), *cmd], stdout=log, stderr=subprocess.STDOUT,
                                           env={**os.environ, "GOMAXPROCS": "1", "TOKIO_WORKER_THREADS": "1"})
                try:
                    wait_ready(process, secure, log, root / "cert.pem")
                    wait_ready(process, plain, log)
                    if args.layer4:
                        assert_sni_rejected(secure, root / "cert.pem")
                    pids = [process.pid, *(nginx_workers(process.pid) if implementation == "nginx" else [])]
                    cases = [("http-static", "keep", f"http://localhost:{plain}/sample"),
                             ("tls-keepalive", "keep", f"https://localhost:{secure}/sample"),
                             ("tls-reconnect", "new", f"https://localhost:{secure}/sample"),
                             ("streaming-post", "post", f"https://localhost:{secure}/proxy")]
                    if args.layer4:
                        cases = [("tcp-keepalive", "keep", f"http://localhost:{plain}/sample"),
                                 ("tcp-reconnect", "new", f"http://localhost:{plain}/sample"),
                                 ("tls-passthrough-keepalive", "keep", f"https://localhost:{secure}/sample"),
                                 ("tls-passthrough-reconnect", "new", f"https://localhost:{secure}/sample")]
                    elif implementation in ("raddy", "raddy-baseline"):
                        cases.append(("streaming-post-proxy-v1", "post", f"https://localhost:{secure}/proxy-pp"))
                    for label, script, url in cases:
                        if args.case and label not in args.case:
                            continue
                        for run in range(1, args.runs + 1):
                            invoke = ["taskset", "-c", str(cpus[1]), "wrk", "-t1", f"-c{args.connections}", "--timeout", "3s", "-s", str(root / f"{script}.lua")]
                            subprocess.run(invoke + ["-d2s", url], check=True, capture_output=True, timeout=10)
                            cpu0, rss0 = sample(pids)
                            result = subprocess.run(invoke + [f"-d{args.seconds}s", url], check=True, capture_output=True, text=True, timeout=args.seconds + 12).stdout
                            cpu1, rss1 = sample(pids)
                            fields = list(map(int, re.search(r"^RESULT (.+)$", result, re.M)[1].split()))
                            rps = float(re.search(r"Requests/sec:\s+([0-9.]+)", result)[1])
                            print(json.dumps({"server": implementation, "case": label, "run": run,
                                              "rps": rps, "p95_us": fields[1], "p99_us": fields[2],
                                              "errors": dict(zip(("connect", "read", "write", "status", "timeout"), fields[3:])),
                                              "cpu_seconds": round((cpu1-cpu0)/os.sysconf("SC_CLK_TCK"), 2),
                                              "rss_mib": round(max(rss0, rss1)/1048576, 1)}), flush=True)
                finally:
                    stop(process)


def wait_ready(process, port, log, cert=None):
    context = ssl.create_default_context(cafile=str(cert)) if cert else None
    deadline = time.monotonic() + 6
    while True:
        try:
            with ExitStack() as connections:
                conn = connections.enter_context(socket.create_connection(("127.0.0.1", port), 1))
                if context:
                    conn = connections.enter_context(context.wrap_socket(conn, server_hostname="localhost"))
                conn.sendall(b"GET /sample HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                data = bytearray()
                while chunk := conn.recv(4096):
                    data.extend(chunk)
                assert data.startswith(b"HTTP/1.1 200 ") and data.endswith(b"r" * 1024), data
                return
        except OSError:
            if time.monotonic() >= deadline or process.poll() is not None:
                log.seek(0)
                raise RuntimeError(log.read())
            time.sleep(0.05)


def assert_sni_rejected(port, cert):
    context = ssl.create_default_context(cafile=str(cert))
    context.check_hostname = False
    with socket.create_connection(("127.0.0.1", port), 2) as sock:
        try:
            with context.wrap_socket(sock, server_hostname="unmatched.example.test"):
                raise AssertionError("Proxy forwarded an unmatched TLS SNI")
        except (ssl.SSLEOFError, ConnectionResetError):
            pass


def sys_is_linux():
    return os.uname().sysname == "Linux"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("raddy", type=lambda path: str(Path(path).resolve()))
    parser.add_argument("--nginx", default="nginx")
    parser.add_argument("--caddy", type=lambda path: str(Path(path).resolve()) if "/" in path else path,
                        help="Include Caddy using this binary")
    parser.add_argument("--baseline", type=lambda path: str(Path(path).resolve()))
    parser.add_argument("--case", action="append", choices=("http-static", "tls-keepalive", "tls-reconnect",
                                                             "streaming-post", "streaming-post-proxy-v1",
                                                             "tcp-keepalive", "tcp-reconnect",
                                                             "tls-passthrough-keepalive", "tls-passthrough-reconnect"))
    parser.add_argument("--layer4", action="store_true", help="Compare TCP proxies and SNI-routed TLS passthrough")
    parser.add_argument("--nginx-stream-module", type=lambda path: Path(path).resolve())
    parser.add_argument("--seconds", type=int, default=8)
    parser.add_argument("--connections", type=int, default=32)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    if min(args.seconds, args.connections, args.runs) < 1:
        parser.error("seconds, connections and runs must be positive")
    if args.layer4 and not args.nginx_stream_module:
        parser.error("--layer4 requires --nginx-stream-module")
    if args.case and any((case.startswith(("tcp-", "tls-passthrough-"))) != args.layer4 for case in args.case):
        parser.error("use --layer4 only with TCP and TLS passthrough cases")
    main(args)
