import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from benchmark import distinct_ports, stop


def main(binary):
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        port, secure = distinct_ports()
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', root/'key.pem', '-out', root/'cert.pem'], check=True, capture_output=True)
        f = root/'Raddyfile'
        f.write_text(f'{{\n default_bind 127.0.0.1\n http_port {port}\n https_port {secure}\n}}\n'
                     f'https://localhost:{secure} {{\n tls {root}/cert.pem {root}/key.pem\n respond ok\n}}\n')
        output = root/'raddy.log'
        log = stack.enter_context(output.open('w'))
        process = subprocess.Popen([binary, '--config', f, 'run', '--grace-period-secs', '1'],
                                   env={**os.environ, 'RUST_LOG': 'raddy=info'}, stdout=log, stderr=subprocess.STDOUT)
        stack.callback(stop, process)

        def wait(pattern):
            until = time.monotonic() + 5
            while True:
                text = re.sub(r'\x1b\[[0-9;]*m', '', output.read_text())
                if re.search(pattern, text):
                    return text
                if process.poll() is not None or time.monotonic() >= until:
                    raise AssertionError((pattern, text))
                time.sleep(.02)

        wait(f'listener ready address=127.0.0.1:{secure}')
        for payload in (b'', b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'):
            with socket.create_connection(('127.0.0.1', secure), timeout=3) as conn:
                if payload:
                    conn.sendall(payload)
                conn.shutdown(socket.SHUT_WR)
                while conn.recv(4096):
                    pass
        # A genuine certificate trust error must still be visible at WARN.
        with socket.create_connection(('127.0.0.1', secure), timeout=3) as conn:
            try:
                with ssl.create_default_context().wrap_socket(conn, server_hostname='localhost'):
                    raise AssertionError('untrusted certificate unexpectedly accepted')
            except ssl.SSLCertVerificationError:
                pass
        wait(r'WARN TLS handshake failed')
        process.send_signal(signal.SIGUSR1)
        text = wait(r'TLS handshake summary.*closed=1 invalid_content_type=1 timed_out=0')
        assert text.count('WARN TLS handshake failed') == 1, text
        print('Pre-handshake EOF and invalid content type counted, trust error remains a warning')


if __name__ == '__main__':
    main(str(Path(sys.argv[1]).resolve()))
