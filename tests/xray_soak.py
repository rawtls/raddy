import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import ssl
import struct
import sys
import subprocess
import tempfile
import threading
import time
import uuid


WEB = "web.rc.test"
REAL = "pass.rc.test"
MODES = ("reality", "xhttp", "ws", "grpc")
CHUNK = 8192


def exact(sock, n):
    result = bytearray()
    while len(result) < n:
        data = sock.recv(n - len(result))
        if not data:
            raise EOFError(f"short read: {len(result)}/{n}")
        result.extend(data)
    return bytes(result)


class Origin(socketserver.ThreadingTCPServer):
    daemon_threads = True
    request_queue_size = 256


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            if exact(self.request, 4) != b"HELO":
                return
            self.request.sendall(secrets.token_bytes(16))
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


def ports(count):
    with ExitStack() as sockets:
        result = []
        for _ in range(count):
            sock = sockets.enter_context(socket.socket())
            sock.bind(("127.0.0.1", 0))
            result.append(sock.getsockname()[1])
    return result


def tunnel(proxy_port, origin):
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=30)
    try:
        sock.sendall(b"\x05\x01\x00")
        assert exact(sock, 2) == b"\x05\x00", "SOCKS negotiation"
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", origin))
        reply = exact(sock, 4)
        assert reply[:2] == b"\x05\x00", ("SOCKS connect", reply)
        if reply[3] == 3:
            addrlen = exact(sock, 1)[0]
        else:
            addrlen = {1: 4, 4: 16}[reply[3]]
        exact(sock, addrlen + 2)
        sock.sendall(b"HELO")
        nonce = exact(sock, 16)
        return sock, nonce
    except BaseException:
        sock.close()
        raise


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def sample(pid):
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    return {
        "rss_kib": int(next(x.split()[1] for x in status if x.startswith("VmRSS:"))),
        "fds": len(os.listdir(f"/proc/{pid}/fd")),
    }


def run(args):
    if not Path("/proc/self/fd").is_dir():
        raise RuntimeError("run on Linux")
    with ExitStack() as stack:
        root = Path(
            stack.enter_context(tempfile.TemporaryDirectory(prefix="raddy-xray-"))
        )
        echo = stack.enter_context(Origin(("127.0.0.1", 0), Echo))
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        stack.callback(echo.shutdown)
        origin = echo.server_address[1]
        http_port, https, target, target_http, *rest = ports(12)
        back, socks = dict(zip(MODES, rest[:4])), dict(zip(MODES, rest[4:]))
        id_ = str(uuid.uuid4())
        short = secrets.token_hex(8)
        keys = subprocess.check_output([args.xray, "x25519"], text=True).splitlines()
        private, public = [line.split(":", 1)[1].strip() for line in keys[:2]]
        version = subprocess.check_output(
            [args.xray, "version"], text=True
        ).splitlines()[0]
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=" + WEB,
                "-addext",
                f"subjectAltName=DNS:{WEB},DNS:{REAL}",
                "-keyout",
                root / "key.pem",
                "-out",
                root / "cert.pem",
            ],
            check=True,
            capture_output=True,
        )
        env = {**os.environ, "SSL_CERT_FILE": str(root / "cert.pem")}
        processes = {}

        def launch(name, cmd):
            log = stack.enter_context((root / (name + ".log")).open("w+"))
            process = subprocess.Popen(
                cmd,
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                env=env,
            )
            stack.callback(stop, process)
            processes[name] = process
            return process

        target_cfg = root / "Target.Raddyfile"
        target_cfg.write_text(
            f"{{\n default_bind 127.0.0.1\n http_port {target_http}\n https_port {target}\n}}\nhttps://{REAL}:{target} {{\n tls {root}/cert.pem {root}/key.pem\n respond target\n}}\n"
        )
        launch(
            "target",
            [args.raddy, "--config", target_cfg, "run", "--grace-period-secs", "0"],
        )
        xhttp_scheme = "h2c" if args.xhttp_mode == "stream-up-h2c" else "http"
        rconfig = root / "Raddyfile"

        def configure(marker):
            config = f'''{{
 default_bind 127.0.0.1
 http_port {http_port}
 https_port {https}
 request_timeout {args.idle}s
}}
tls://{REAL}:{https} {{
 proxy 127.0.0.1:{back["reality"]}
}}
https://{WEB}:{https} {{
 tls {root}/cert.pem {root}/key.pem
 handle /ws {{
  reverse_proxy http://127.0.0.1:{back["ws"]}
 }}
 handle /xhttp* {{
  reverse_proxy {xhttp_scheme}://127.0.0.1:{back["xhttp"]}
 }}
 handle /rc.Service/* {{
  reverse_proxy h2c://127.0.0.1:{back["grpc"]}
 }}
 handle {{
  respond "{marker}"
 }}
}}
'''
            tmp = root / "next"
            tmp.write_text(config)
            tmp.replace(rconfig)

        configure("initial")
        ctx = ssl.create_default_context(cafile=str(root / "cert.pem"))

        def marker(expected):
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                if any(p.poll() is not None for p in processes.values()):
                    raise RuntimeError("service exited")
                try:
                    with (
                        socket.create_connection(("127.0.0.1", https), 1) as raw,
                        ctx.wrap_socket(raw, server_hostname=WEB) as sock,
                    ):
                        sock.sendall(
                            f"GET /marker HTTP/1.1\r\nHost: {WEB}\r\nConnection: close\r\n\r\n".encode()
                        )
                        with http.client.HTTPResponse(sock) as response:
                            response.begin()
                            if (
                                response.status == 200
                                and response.read() == expected.encode()
                            ):
                                return
                except OSError:
                    pass
                time.sleep(0.03)
            raise RuntimeError("new HTTPS request did not see generation " + expected)

        raddy = launch(
            "raddy",
            [args.raddy, "--config", rconfig, "run", "--grace-period-secs", "1"],
        )
        marker("initial")
        server_in, client_in, client_out, client_routes = [], [], [], []
        for mode in MODES:
            network = "raw" if mode == "reality" else mode
            inbound = {"network": network}
            outbound = {"network": network}
            if mode == "reality":
                inbound.update(
                    security="reality",
                    realitySettings={
                        "target": f"127.0.0.1:{target}",
                        "serverNames": [REAL],
                        "privateKey": private,
                        "shortIds": [short],
                    },
                )
                outbound.update(
                    security="reality",
                    realitySettings={
                        "serverName": REAL,
                        "fingerprint": "chrome",
                        "password": public,
                        "shortId": short,
                    },
                )
            else:
                outbound.update(
                    security="tls",
                    tlsSettings={
                        "serverName": WEB,
                        "certificates": [
                            {
                                "usage": "verify",
                                "certificateFile": str(root / "cert.pem"),
                            }
                        ],
                        "alpn": ["http/1.1" if mode == "ws" else "h2"],
                    },
                )
                opts = {
                    "ws": ("wsSettings", {"path": "/ws", "host": WEB}),
                    "xhttp": (
                        "xhttpSettings",
                        {"path": "/xhttp", "mode": args.xhttp_mode, "host": WEB},
                    ),
                    "grpc": (
                        "grpcSettings",
                        {"serviceName": "rc.Service", "authority": WEB},
                    ),
                }
                key, value = opts[mode]
                if mode == "xhttp" and args.xhttp_mode == "stream-up-h2c":
                    outbound[key] = {**value, "mode": "stream-up"}
                    inbound[key] = {
                        "path": "/xhttp",
                        "mode": "stream-up",
                        "scStreamUpServerSecs": "1-2",
                    }
                else:
                    inbound[key] = outbound[key] = value
            user = {"id": id_}
            server_user = {"id": id_}
            if mode == "reality":
                user["flow"] = server_user["flow"] = "xtls-rprx-vision"
            server_in.append(
                {
                    "tag": mode,
                    "listen": "127.0.0.1",
                    "port": back[mode],
                    "protocol": "vless",
                    "settings": {"decryption": "none", "clients": [server_user]},
                    "streamSettings": inbound,
                }
            )
            client_in.append(
                {
                    "tag": mode,
                    "listen": "127.0.0.1",
                    "port": socks[mode],
                    "protocol": "socks",
                    "settings": {"udp": False},
                }
            )
            client_out.append(
                {
                    "tag": mode,
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": "127.0.0.1",
                                "port": https,
                                "users": [{**user, "encryption": "none"}],
                            }
                        ]
                    },
                    "streamSettings": outbound,
                }
            )
            client_routes.append(
                {"type": "field", "inboundTag": [mode], "outboundTag": mode}
            )
        confs = {
            "server": {
                "inbounds": server_in,
                "outbounds": [
                    {"tag": "deny", "protocol": "blackhole"},
                    {
                        "tag": "local",
                        "protocol": "freedom",
                        "settings": {
                            "finalRules": [
                                {
                                    "action": "allow",
                                    "ip": ["127.0.0.1/32"],
                                    "network": "tcp",
                                    "port": origin,
                                },
                                {"action": "block"},
                            ]
                        },
                    },
                ],
                "routing": {
                    "rules": [
                        {
                            "type": "field",
                            "ip": ["127.0.0.1"],
                            "port": origin,
                            "network": "tcp",
                            "outboundTag": "local",
                        }
                    ]
                },
            },
            "client": {
                "inbounds": client_in,
                "outbounds": client_out,
                "routing": {"rules": client_routes},
            },
        }
        for name, cfg in confs.items():
            cfg["log"] = {"loglevel": "error", "access": "none"}
            path = root / (name + ".json")
            path.write_text(json.dumps(cfg))
            test = subprocess.run(
                [args.xray, "run", "-test", "-c", path],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            if test.returncode:
                raise RuntimeError(
                    f"{name} configuration failed: "
                    + test.stderr.replace(private, "[key]").replace(id_, "[id]")
                )
            launch(name, [args.xray, "run", "-c", path])
        try:
            for mode in MODES:
                until = time.monotonic() + 8
                while True:
                    try:
                        sock, nonce = tunnel(socks[mode], origin)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= until:
                            raise
                        time.sleep(0.05)
                with sock:
                    sock.sendall(nonce)
                    assert exact(sock, 16) == nonce
                print(json.dumps({"preflight": mode, "status": "ok"}), flush=True)
            stop_at = threading.Event()
            established = threading.Barrier(len(MODES) * args.lanes + 1, timeout=30)

            def lane(mode):
                sock, nonce = tunnel(socks[mode], origin)
                sendhash = hashlib.sha256()
                recvhash = hashlib.sha256()
                count = 0
                with sock:
                    established.wait()
                    deadline = time.monotonic() + args.seconds
                    while time.monotonic() < deadline and not stop_at.is_set():
                        data = nonce + os.urandom(CHUNK - 16)
                        sock.sendall(data)
                        got = exact(sock, len(data))
                        assert got == data, (mode, count, "echo mismatch")
                        sendhash.update(data)
                        recvhash.update(got)
                        count += len(got)
                        if count == CHUNK:
                            time.sleep(min(1.25, args.idle / 2))
                        else:
                            stop_at.wait(args.interval)
                assert count and sendhash.digest() == recvhash.digest()
                return {
                    "mode": mode,
                    "bytes_each_direction": count,
                    "sha256": sendhash.hexdigest(),
                }

            with ThreadPoolExecutor(max_workers=len(MODES) * args.lanes) as pool:
                futures = [
                    pool.submit(lane, m) for m in MODES for _ in range(args.lanes)
                ]
                try:
                    established.wait()
                    start = time.monotonic()
                    next_reload = start + args.reload_after
                    next_sample = start
                    reloads = 0
                    while not all(f.done() for f in futures):
                        for f in futures:
                            if f.done():
                                f.result()
                        now = time.monotonic()
                        if now >= next_reload:
                            reloads += 1
                            generation = "reload-" + str(reloads)
                            configure(generation)
                            raddy.send_signal(signal.SIGUSR1)
                            marker(generation)
                            for m in MODES:
                                sock, token = tunnel(socks[m], origin)
                                with sock:
                                    sock.sendall(token)
                                    assert exact(sock, 16) == token
                            print(
                                json.dumps(
                                    {
                                        "reload": reloads,
                                        "new_tunnels_verified": list(MODES),
                                    }
                                ),
                                flush=True,
                            )
                            next_reload = now + args.reload_every
                        if now >= next_sample:
                            print(
                                json.dumps(
                                    {
                                        "elapsed_s": round(now - start, 1),
                                        "processes": {
                                            k: sample(processes[k].pid)
                                            for k in ("raddy", "client", "server")
                                        },
                                    }
                                ),
                                flush=True,
                            )
                            next_sample = now + 60
                        time.sleep(0.15)
                    rows = [f.result() for f in futures]
                    assert reloads >= 1
                    print(
                        json.dumps(
                            {
                                "status": "passed",
                                "xray": version,
                                "seconds": round(time.monotonic() - start, 1),
                                "reloads": reloads,
                                "lanes": args.lanes,
                                "xhttp_mode": args.xhttp_mode,
                                "verified_bytes_each_direction": {
                                    m: sum(
                                        r["bytes_each_direction"]
                                        for r in rows
                                        if r["mode"] == m
                                    )
                                    for m in MODES
                                },
                                "hashes": [r["sha256"] for r in rows],
                            }
                        ),
                        flush=True,
                    )
                finally:
                    stop_at.set()
                    established.abort()
        except BaseException:
            for name in ("server", "client", "raddy", "target"):
                with (root / (name + ".log")).open("rb") as output:
                    output.seek(max(0, os.fstat(output.fileno()).st_size - 5000))
                    log = (
                        output.read()
                        .decode(errors="replace")
                        .replace(private, "[key]")
                        .replace(id_, "[id]")
                    )
                print(name, log, file=sys.stderr)
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Loopback real-Xray VLESS reload and integrity soak (Linux)"
    )
    parser.add_argument("raddy", type=lambda s: str(Path(s).resolve()))
    parser.add_argument("xray", type=lambda s: str(Path(s).resolve()))
    parser.add_argument(
        "--xhttp-mode",
        choices=("packet-up", "stream-up", "stream-up-h2c"),
        default="packet-up",
    )
    parser.add_argument("--seconds", type=int, default=45)
    parser.add_argument("--lanes", type=int, default=1)
    parser.add_argument("--idle", type=int, default=6)
    parser.add_argument("--interval", type=float, default=0.12)
    parser.add_argument("--reload-after", type=int, default=12)
    parser.add_argument("--reload-every", type=int, default=900)
    a = parser.parse_args()
    if (
        min(a.seconds, a.lanes, a.idle, a.interval, a.reload_after, a.reload_every) <= 0
        or a.seconds <= a.reload_after + 2
    ):
        parser.error("positive settings and a reload before the end are required")
    run(a)
