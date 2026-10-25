"""Local integration fixture; needs Paramiko, never uses existing SSH keys or servers."""

import base64
import hashlib
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

try:
    import paramiko
except ImportError:
    print("SKIP: install paramiko to run the local SSH integration test")
    sys.exit(77)

BYEDPI_ARGS = "-f -1 -t 8 -S -R 1"
PAYLOAD = b"SSH through embedded ByeDPI\x00" * 300


def receive(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        assert part, "Unexpected EOF"
        result.extend(part)
    return bytes(result)


class Server(paramiko.ServerInterface):
    def __init__(self, client_key, authentications):
        self.client_key = client_key
        self.authentications = authentications

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_publickey(self, username, key):
        if username == "fixture" and key == self.client_key:
            self.authentications.append(username)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        if destination == ("fixture.test", 443):
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SshFixture:
    def __init__(self, host_key, client_key, disconnect_message=None):
        self.host_key = host_key
        self.client_key = client_key
        self.disconnect_message = disconnect_message
        self.authentications = []
        self.stopping = threading.Event()
        self.transports = []
        self.workers = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self.serve, args=(connection,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def serve(self, connection):
        transport = paramiko.Transport(connection)
        self.transports.append(transport)
        transport.add_server_key(self.host_key)
        try:
            transport.start_server(server=Server(self.client_key, self.authentications))
            if self.disconnect_message:
                message = paramiko.Message()
                message.add_byte(b"\x01")  # SSH_MSG_DISCONNECT
                message.add_int(11)  # SSH_DISCONNECT_BY_APPLICATION
                message.add_string(self.disconnect_message)
                message.add_string("en")
                transport._send_message(message)
                return
            while transport.is_active() and not self.stopping.is_set():
                channel = transport.accept(0.2)
                if channel is None:
                    continue
                channel.settimeout(5)
                try:
                    payload = receive(channel, len(PAYLOAD))
                    channel.sendall(payload)
                    channel.shutdown_write()
                    # Let the client consume EOF and close the channel normally.
                    while channel.recv(1024):
                        pass
                finally:
                    channel.close()
        except (EOFError, OSError, paramiko.SSHException):
            pass  # Wrong-host-key and shutdown scenarios close the SSH transport.
        finally:
            transport.close()

    def close(self):
        self.stopping.set()
        self.listener.close()
        for transport in self.transports:
            transport.close()
        self.thread.join(2)
        for worker in self.workers:
            worker.join(2)


def run_proxy(binary, fixture, key_path, fingerprint, options, workdir, reject=False, expected_diagnostic=None):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    command = [
        binary, "--ssh-user", "fixture", "--ssh-host", "127.0.0.1",
        "--ssh-port", str(fixture.port), "--ssh-host-key-sha256", fingerprint,
        "--ssh-private-key-path", str(key_path), "--listen-port", str(port),
    ]
    if options is not None:
        command.extend(["--byedpi-args", options])
    with (workdir / "proxy.log").open("w+") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, "Proxy exited before listening"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "Proxy startup timed out"
                    time.sleep(0.02)
            authenticated_before = len(fixture.authentications)
            protocols = ("socks",) if reject else ("socks", "http")
            for protocol in protocols:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                    if protocol == "socks":
                        client.sendall(b"\x05\x01\x00")
                        assert receive(client, 2) == b"\x05\x00"
                        hostname = b"fixture.test"
                        client.sendall(b"\x05\x01\x00\x03" + bytes([len(hostname)]) + hostname + struct.pack("!H", 443))
                        reply = receive(client, 10)
                        if reject:
                            assert reply[1] != 0, "Rejected SSH connection unexpectedly succeeded"
                            if expected_diagnostic is None:
                                assert len(fixture.authentications) == authenticated_before
                            continue
                        assert reply[1] == 0, f"SOCKS CONNECT failed: {reply!r}"
                    else:
                        client.sendall(b"CONNECT fixture.test:443 HTTP/1.1\r\nHost: fixture.test:443\r\n\r\n")
                        reply = bytearray()
                        while not reply.endswith(b"\r\n\r\n"):
                            reply.extend(receive(client, 1))
                            assert len(reply) < 4096
                        assert reply.startswith(b"HTTP/1.1 200"), reply
                    client.sendall(PAYLOAD)
                    assert receive(client, len(PAYLOAD)) == PAYLOAD
            process.terminate()
            assert process.wait(timeout=5) == 0, "Proxy did not stop cleanly"
            log.seek(0)
            output = log.read()
            if options is not None:
                assert "Embedded ByeDPI listening" in output
            if expected_diagnostic is not None:
                assert expected_diagnostic in output, output
                assert "detail='" in output and "detail=''" not in output, output
        except Exception:
            log.seek(0)
            print(log.read())
            raise
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def main():
    binary = str(Path(sys.argv[1]).resolve())
    host_key = paramiko.RSAKey.generate(2048)
    client_key = paramiko.RSAKey.generate(2048)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(host_key.asbytes()).digest()).decode().rstrip("=")
    fixture = SshFixture(host_key, client_key)
    try:
        with tempfile.TemporaryDirectory(prefix="byedpi-ssh-") as directory:
            workdir = Path(directory)
            key_path = workdir / "fixture-key"
            client_key.write_private_key_file(str(key_path))
            run_proxy(binary, fixture, key_path, fingerprint, BYEDPI_ARGS, workdir)
            print("PASS: SSH authentication, SOCKS5 and HTTP CONNECT through embedded ByeDPI")
            run_proxy(binary, fixture, key_path, "SHA256:" + "A" * 43, BYEDPI_ARGS, workdir, reject=True)
            print("PASS: incorrect SSH host key rejected before authentication")
            run_proxy(binary, fixture, key_path, fingerprint, None, workdir)
            print("PASS: direct SSH mode remains functional")
            real_strategy = "-d1 -s1+s -d1+s -s3+s -d6+s -s12+s -d14+s -s20+s -d24+s -s30+s -a1"
            run_proxy(binary, fixture, key_path, fingerprint, real_strategy, workdir)
            print("PASS: supplied ByeDPI strategy accepts SSH traffic on the local fixture")
            disconnect_fixture = SshFixture(host_key, client_key, "fixture diagnostic disconnect")
            try:
                run_proxy(binary, disconnect_fixture, key_path, fingerprint, BYEDPI_ARGS, workdir,
                          reject=True, expected_diagnostic="SSH server disconnect: reason=11, message='fixture diagnostic disconnect'")
                print("PASS: SSH server disconnect reason is preserved in diagnostics")
            finally:
                disconnect_fixture.close()
    finally:
        fixture.close()


if __name__ == "__main__":
    main()
