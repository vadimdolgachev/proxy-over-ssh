"""Exercise setup cleanup and CLI failures using loopback and placeholder SSH configuration."""

import collections
from contextlib import contextmanager
import os
from pathlib import Path
import resource
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


def command(binary, port):
    return [
        binary, "--ssh-user", "fixture", "--ssh-host", "127.0.0.1", "--ssh-port", "9",
        "--ssh-host-key-sha256", "SHA256:" + "A" * 43,
        "--ssh-private-key-path", "/dev/null", "--listen-port", str(port),
    ]


def limit_descriptors():
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))


@contextmanager
def running_proxy(binary):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with tempfile.TemporaryFile(mode="w+") as log:
        process = subprocess.Popen(command(binary, port), stdout=log, stderr=subprocess.STDOUT,
                                   preexec_fn=limit_descriptors)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, "Proxy exited before listening"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "Proxy startup timed out"
                    time.sleep(0.01)
            yield process, port, log
        except BaseException:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            log.seek(0)
            print(log.read())
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def descriptor_counts(process):
    assert process.poll() is None, f"Proxy exited with code {process.returncode}"
    counts = collections.Counter()
    for entry in Path(f"/proc/{process.pid}/fd").iterdir():
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        counts["socket" if target.startswith("socket:") else target] += 1
    return counts


def receive_to_eof(client):
    response = bytearray()
    while True:
        part = client.recv(4096)
        if not part:
            return bytes(response)
        response.extend(part)
        assert len(response) < 16384, "Unexpectedly large response"


def receive_exact(client, size):
    response = bytearray()
    while len(response) < size:
        part = client.recv(size - len(response))
        assert part, "Unexpected EOF"
        response.extend(part)
    return bytes(response)


def test_cleanup(binary):
    with running_proxy(binary) as (process, port, _):
        time.sleep(0.05)
        baseline = descriptor_counts(process)
        for protocol in ("socks", "http"):
            for _ in range(500):
                with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                    if protocol == "socks":
                        client.sendall(b"\x05\x01\x00")
                        assert receive_exact(client, 2) == b"\x05\x00", "SOCKS greeting failed"
                        client.shutdown(socket.SHUT_WR)
                        receive_to_eof(client)
                    else:
                        client.sendall(b"broken\r\n\r\n")
                        assert receive_to_eof(client).startswith(b"HTTP/1.1 400"), "Expected bad-request response"
            deadline = time.monotonic() + 2
            while True:
                counts = descriptor_counts(process)
                if counts["anon_inode:[eventfd]"] <= baseline["anon_inode:[eventfd]"] + 2 and counts["socket"] == 1:
                    break
                assert time.monotonic() < deadline, f"Setup descriptors retained after {protocol}: {counts}"
                time.sleep(0.01)
            assert counts["anon_inode:[timerfd]"] <= 65, counts  # Bounded timer cache plus statistics timer.
            print(f"PASS: 500 {protocol} clients, FD limit 128, remaining descriptors: {dict(counts)}")
        process.terminate()
        assert process.wait(timeout=5) == 0, "SIGTERM must remain a successful shutdown"


def test_timeout(binary):
    with running_proxy(binary) as (process, port, _):
        with socket.create_connection(("127.0.0.1", port), timeout=40) as client:
            started = time.monotonic()
            client.sendall(b"\x05\x01\x00")
            assert receive_exact(client, 2) == b"\x05\x00"
            # Never send the SOCKS CONNECT request; the setup deadline must close this client.
            receive_to_eof(client)
            elapsed = time.monotonic() - started
            assert 29 <= elapsed < 38, f"Unexpected setup deadline: {elapsed:.2f}s"
            assert process.poll() is None, "A single setup timeout must not stop the server"
            print(f"PASS: unfinished setup cancelled after {elapsed:.2f}s")


def test_failure_exit(binary):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        result = subprocess.run(command(binary, listener.getsockname()[1]),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5, text=True)
        assert result.returncode == 1, f"Fatal server error returned {result.returncode}:\n{result.stdout}"
        assert "Failed to bind server socket" in result.stdout, result.stdout
        print("PASS: occupied listen port returns exit code 1")


def test_shutdown(binary):
    for stop_signal in (signal.SIGTERM, signal.SIGINT):
        for iteration in range(100):
            with running_proxy(binary) as (process, port, log):
                stopped = threading.Event()
                traffic_started = threading.Event()

                def traffic():
                    while not stopped.is_set():
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.2) as client:
                                client.sendall(b"broken\r\n\r\n")
                                traffic_started.set()
                                client.recv(4096)
                        except OSError:
                            if process.poll() is not None:
                                return
                            stopped.wait(0.001)

                workers = []
                try:
                    for _ in range(3):
                        worker = threading.Thread(target=traffic, daemon=True)
                        worker.start()
                        workers.append(worker)
                    assert traffic_started.wait(timeout=2), "Connection traffic did not start"
                    time.sleep((iteration % 10 + 1) * 0.001)
                    process.send_signal(stop_signal)
                    assert process.wait(timeout=5) == 0, (
                        f"{stop_signal.name} under traffic returned {process.returncode}, iteration {iteration}"
                    )
                    log.seek(0)
                    assert "Proxy exception:" not in log.read(), "Graceful shutdown reported a proxy failure"
                finally:
                    stopped.set()
                    for worker in workers:
                        worker.join(timeout=1)
                        assert not worker.is_alive(), "Connection traffic worker did not stop"
        print(f"PASS: 100 {stop_signal.name} shutdowns with concurrent connections")


if __name__ == "__main__":
    tests = {"cleanup": test_cleanup, "timeout": test_timeout, "failure_exit": test_failure_exit,
             "shutdown": test_shutdown}
    tests[sys.argv[2]](str(Path(sys.argv[1]).resolve()))
