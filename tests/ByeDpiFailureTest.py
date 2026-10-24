"""Exercise a real CLI fatal ByeDPI exit using only local sockets and placeholder configuration."""

import errno
import os
from pathlib import Path
import pty
import re
import resource
import select
import socket
import subprocess
import sys
import time


def limit_descriptors():
    resource.setrlimit(resource.RLIMIT_NOFILE, (48, 48))


def main():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        proxy_port = reservation.getsockname()[1]
    master, slave = pty.openpty()
    command = [
        str(Path(sys.argv[1]).resolve()),
        "--ssh-user", "fixture", "--ssh-host", "127.0.0.1", "--ssh-port", "22",
        "--ssh-host-key-sha256", "SHA256:" + "A" * 43,
        "--ssh-private-key-path", "/dev/null", "--listen-port", str(proxy_port),
        "--byedpi-args", "--split 2",
    ]
    process = subprocess.Popen(command, stdout=slave, stderr=subprocess.STDOUT, preexec_fn=limit_descriptors)
    os.close(slave)
    output = bytearray()
    clients = []

    def read_output():
        if select.select([master], [], [], 0.1)[0]:
            try:
                output.extend(os.read(master, 65536))
            except OSError as error:
                if error.errno != errno.EIO:
                    raise

    try:
        deadline = time.monotonic() + 5
        while b"SOCKS5 / HTTP CONNECT proxy started" not in output:
            read_output()
            assert process.poll() is None and time.monotonic() < deadline, output.decode(errors="replace")
        match = re.search(rb"Embedded ByeDPI listening on 127\.0\.0\.1:(\d+)", output)
        assert match, output.decode(errors="replace")
        port = int(match.group(1))
        for _ in range(80):
            try:
                clients.append(socket.create_connection(("127.0.0.1", port), timeout=0.1))
            except OSError:
                break
        deadline = time.monotonic() + 5
        while process.poll() is None and time.monotonic() < deadline:
            read_output()
        assert process.wait(timeout=2) == 1, output.decode(errors="replace")
        read_output()
        assert b"Embedded ByeDPI event loop stopped unexpectedly: errno=" in output, output.decode(errors="replace")
        print("PASS: fatal ByeDPI accept failure stops the CLI with exit code 1")
    finally:
        for client in clients:
            client.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)


if __name__ == "__main__":
    main()
