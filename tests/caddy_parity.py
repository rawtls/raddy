import http.client
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request("GET", path, headers=headers or {})
        reply = conn.getresponse()
        return reply.status, reply.read(), reply.getheader("X-Test"), reply.getheader("Content-Range"), reply.getheader("Content-Type")
    finally:
        conn.close()


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def main(binary):
    caddy = shutil.which("caddy")
    if not caddy:
        raise SystemExit("Caddy 2.10.2 must be on PATH")
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        (root / "assets").mkdir()
        (root / "assets" / "sample.txt").write_text("abcdef")
        (root / "assets" / "index.html").write_text("spa")
        (root / "rules").write_text("respond /imported imported\n")
        template = r'''
http://127.0.0.1:PORT {
    bind 127.0.0.1
    root * ROOT/assets
    @regexp path_regexp `^/items/(?P<id>\d+)$`
    @query query mode=on
    @cel expression `method("GET") && path("/cel")`
    handle @regexp {
        header X-Test "{re.regexp.id}"
        respond "item {re.regexp.id}"
    }
    handle @query {
        respond query
    }
    handle @cel {
        respond cel
    }
    handle_path /static/* {
        file_server
    }
    handle /encoded%2Fname {
        respond encoded
    }
    handle /header-override {
        header /header-override Content-Type application/x-parity
        respond "header checked"
    }
    handle /failure {
        error "not there" 404
    }
    handle_errors 4xx {
        respond "error {err.status_code}"
    }
    handle /imported {
        import rules
    }
    handle {
        try_files {path} /index.html
        file_server
    }
}
'''
        addresses = []
        for is_raddy in (False, True):
            listen = port()
            cfg = root / ("Raddyfile" if is_raddy else "Caddyfile")
            config = template.replace("PORT", str(listen)).replace("ROOT", str(root))
            cfg.write_text(config if is_raddy else "{\n admin off\n persist_config off\n}\n" + config)
            command = ([binary, "--config", cfg, "run", "--grace-period-secs", "1"] if is_raddy
                       else [caddy, "run", "--config", cfg, "--adapter", "caddyfile"])
            log = stack.enter_context((root / f"{listen}.log").open("w+"))
            process = subprocess.Popen(command, cwd=root, stdout=log, stderr=subprocess.STDOUT)
            stack.callback(stop, process)
            deadline = time.monotonic() + 6
            while True:
                try:
                    request(listen, "/imported")
                    break
                except OSError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    time.sleep(0.05)
            addresses.append(listen)
        cases = [
            ("/items/%34%32", None, (200, b"item 42", "42", None)),
            ("/query?mode=off&mode=on", None, (200, b"query", None, None)),
            ("/cel", None, (200, b"cel", None, None)),
            ("/static/sample.txt", {"Range": "bytes=1-3"}, (206, b"bcd", None, "bytes 1-3/6")),
            ("/encoded%2fname", None, (200, b"encoded", None, None)),
            ("/failure", None, (404, b"error 404", None, None)),
            ("/header-override", None, (200, b"header checked", None, None, "application/x-parity")),
            ("/imported", None, (200, b"imported", None, None)),
            ("/deep/app/path", None, (200, b"spa", None, None)),
        ]
        for path, headers, expected in cases:
            actual = [request(listen, path, headers)[:len(expected)] for listen in addresses]
            assert actual == [expected, expected], (path, expected, actual)
        print(f"{len(cases)} HTTP routing cases matched Caddy")


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve()))
