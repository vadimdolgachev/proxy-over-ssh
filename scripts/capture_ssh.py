#!/usr/bin/env python3
"""Capture an SSH connection on both Linux endpoints using an existing SSH alias."""

import argparse
import contextlib
import ipaddress
import json
import math
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def run(command, timeout=20, check=True, **kwargs):
    return subprocess.run(command, stdin=subprocess.DEVNULL, timeout=timeout, check=check, **kwargs)


def validate_pcap(path):
    with path.open("rb") as capture:
        header = capture.read(24)
    if len(header) < 24 or header[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                                            b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        raise RuntimeError(f"missing or invalid PCAP header: {path}")


def stop_process(process, privilege=()):
    if process is None or process.poll() is not None:
        return
    for sig in ("INT", "TERM", "KILL"):
        subprocess.run([*privilege, "kill", "-" + sig, str(process.pid)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5, check=False)
        try:
            process.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            pass
    raise RuntimeError(f"could not stop capture process {process.pid}")


def wait_for_captures(captures):
    deadline = time.monotonic() + 15
    while True:
        for process, log_path in captures:
            if process.poll() is not None:
                detail = log_path.read_text(errors="replace").strip()
                raise RuntimeError(f"capture exited during startup: {detail or process.returncode}; see {log_path}")
        if all(b"listening on " in path.read_bytes() for _, path in captures):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("tcpdump did not become ready within 15 seconds; see capture logs")
        time.sleep(0.1)


def check_captures(captures):
    for process, path in captures:
        if process.poll() is not None:
            raise RuntimeError(f"capture stopped unexpectedly; see {path}")


def stop_ssh(process):
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)


@contextlib.contextmanager
def logged_ssh(command, log_path):
    started = time.time()
    monotonic_start = time.monotonic()
    with log_path.open("w") as log:
        log.write(f"{started:.6f} command: {shlex.join(command)}\n")
        log.flush()
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)

        def copy_output():
            for line in process.stdout:
                log.write(f"{time.time():.6f} " + line.decode(errors="replace"))
                log.flush()

        reader = threading.Thread(target=copy_output, daemon=True)
        reader.start()
        try:
            yield process
        finally:
            stop_ssh(process)
            reader.join()
            process.stdout.close()
            elapsed = time.monotonic() - monotonic_start
            log.write(f"{time.time():.6f} exit={process.returncode} elapsed={elapsed:.3f}s\n")


def ssh_attempt(command, log_path, timeout):
    started = time.time()
    monotonic_start = time.monotonic()
    expired = False
    with logged_ssh(command, log_path) as process:
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            expired = True
    elapsed = time.monotonic() - monotonic_start
    return dict(start_epoch=started, elapsed_seconds=elapsed,
                exit_code=process.returncode, timed_out=expired, log=log_path.name)


def wait_for_control(process, command, socket_path, captures, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        check_captures(captures)
        if process.poll() is not None:
            raise RuntimeError(f"control SSH exited with code {process.returncode}; see control.log and client.pcap")
        if Path(socket_path).exists():
            try:
                check = run(command, timeout=max(0.001, min(2, deadline - time.monotonic())), check=False,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if check.returncode == 0:
                    return
            except subprocess.TimeoutExpired:
                pass
        time.sleep(0.1)
    raise TimeoutError(f"control SSH was not ready after {timeout}s; see control.log and client.pcap")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="direct SSH destination or alias, e.g. classic-sapphire")
    parser.add_argument("--attempts", type=positive_int, default=5, help="new SSH connections (default: 5)")
    parser.add_argument("--connect-timeout", type=positive_int, default=10, help="SSH ConnectTimeout (default: 10)")
    parser.add_argument("--duration", type=positive_int, default=60,
                        help="maximum capture window in seconds (default: 60)")
    parser.add_argument("--ip-qos", help="test IPQoS, e.g. none or 16; otherwise use SSH configuration")
    parser.add_argument("--manual", action="store_true", help="capture only; reproduce the issue yourself")
    parser.add_argument("--interface", default="any", help="local capture interface (default: any)")
    parser.add_argument("--remote-interface", default="any", help="server capture interface (default: any)")
    parser.add_argument("--output", type=Path, help="new output directory (default: private directory in /tmp)")
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must not start with '-'")
    for executable in ("ssh", "tcpdump", "timeout"):
        if not shutil.which(executable):
            parser.error(f"required local command is missing: {executable}")
    privilege = [] if os.geteuid() == 0 else ["sudo", "-n"]
    if privilege and not shutil.which("sudo"):
        parser.error("sudo is required for the local capture")

    os.umask(0o077)
    try:
        if args.output:
            args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
            output = args.output.resolve()
        else:
            output = Path(tempfile.mkdtemp(prefix="ssh-capture-"))
    except OSError as error:
        parser.error(f"cannot create output directory: {error}")
    print(f"Output: {output}", flush=True)
    metadata = dict(host=args.host, manual=args.manual, connect_timeout=args.connect_timeout,
                    duration=args.duration, ip_qos=args.ip_qos, attempts=[], warnings=[])
    remote_dir = None
    remote_privilege = []
    local_capture = remote_capture = control_process = None
    local_ready = False
    server_pcap_saved = False
    status = 0

    def warn(message):
        metadata["warnings"].append(message)
        print(f"Warning: {message}", file=sys.stderr, flush=True)

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    with tempfile.TemporaryDirectory(prefix="ssh-cap-ctl-") as control_dir, contextlib.ExitStack() as stack:
        control_path = str(Path(control_dir) / "socket")
        common = ["ssh", "-T", "-oBatchMode=yes", "-oClearAllForwardings=yes",
                  "-oForwardAgent=no", "-oForwardX11=no", "-oConnectionAttempts=1",
                  "-oForkAfterAuthentication=no",
                  f"-oConnectTimeout={args.connect_timeout}"]
        control = [*common, "-S", control_path, "-oControlMaster=no"]

        def remote_command(argv):
            # Fail if the master is lost instead of silently opening an uncaptured control connection.
            return [*control, "-oProxyCommand=false", args.host, shlex.join(argv)]

        def remote(argv, **kwargs):
            return run(remote_command(argv), **kwargs)

        try:
            if privilege:
                subprocess.run(["sudo", "-v"], check=True)
            config = run([*common, "-G", args.host], capture_output=True, text=True).stdout
            settings = dict(line.split(" ", 1) for line in config.splitlines() if " " in line)
            if any(settings.get(key, "none") != "none" for key in ("proxyjump", "proxycommand")):
                raise RuntimeError("this script requires direct SSH; ProxyJump/ProxyCommand are unsupported")
            destination = settings["hostname"]
            destination_port = int(settings.get("port", "22"))
            local_filter = f"host {destination} and tcp port {destination_port}"
            metadata["local_filter"] = local_filter
            tcpdump = ["tcpdump", "-nn", "-s", "0", "-U", "-i"]
            local_log = output / "client-tcpdump.log"
            # Preserve the terminal session authenticated by sudo -v. timeout gives
            # the capture its own process group and also covers SSH setup failures.
            local_guard = str(args.duration + args.connect_timeout + 90)
            local_capture = subprocess.Popen(
                [*privilege, "env", "LC_ALL=C", "timeout", "-s", "INT", "-k", "5", local_guard,
                 *tcpdump, args.interface, "-w", "-", local_filter],
                stdin=subprocess.DEVNULL,
                stdout=stack.enter_context((output / "client.pcap").open("wb")),
                stderr=stack.enter_context(local_log.open("wb")))
            wait_for_captures([(local_capture, local_log)])
            local_ready = True
            metadata["local_capture_ready_epoch"] = time.time()
            print("Opening the control connection...", flush=True)
            control_process = stack.enter_context(logged_ssh(
                [*common, "-vvv", "-M", "-N", "-S", control_path, "-oControlPersist=no", args.host],
                output / "control.log"))
            metadata["control_connection_ready"] = False
            wait_for_control(control_process, [*control, "-O", "check", args.host], control_path,
                             [(local_capture, local_log)], args.connect_timeout + 10)
            metadata["control_connection_ready"] = True

            before = time.time()
            info = remote(["sh", "-c", """
set -eu
command -v tcpdump >/dev/null
command -v timeout >/dev/null
if [ "$(id -u)" != 0 ]; then sudo -n true; fi
capture_dir=$(mktemp -d /tmp/ssh-capture.XXXXXXXXXX)
printf 'SSH_CAPTURE_META %s %s %s %s\n' "$capture_dir" "$SSH_CONNECTION" "$(id -u)" "$(date +%s.%N)"
"""], capture_output=True, text=True)
            after = time.time()
            fields = next(line.split() for line in info.stdout.splitlines() if line.startswith("SSH_CAPTURE_META "))
            _, remote_dir, client_ip, client_port, server_ip, server_port, remote_uid, remote_epoch = fields
            ipaddress.ip_address(client_ip)
            ipaddress.ip_address(server_ip)
            if not server_port.isdecimal() or not client_port.isdecimal():
                raise RuntimeError("unexpected SSH_CONNECTION ports")
            remote_privilege = [] if remote_uid == "0" else ["sudo", "-n"]
            metadata.update(control_connection=dict(client_ip=client_ip, client_port=int(client_port),
                                                    server_ip=server_ip, server_port=int(server_port)),
                            remote_directory=remote_dir,
                            clock_sample=dict(local_before_epoch=before, local_after_epoch=after,
                                              remote_epoch=float(remote_epoch),
                                              round_trip_seconds=after - before,
                                              estimated_remote_offset_seconds=(float(remote_epoch)
                                                                               - (before + after) / 2)))
            remote_filter = f"host {client_ip} and tcp port {server_port}"
            metadata["remote_filter"] = remote_filter
            guard = str(args.duration + 30)
            remote_pcap = remote_dir + "/server.pcap"
            remote_pid = shlex.quote(remote_dir + "/capture.pid")
            remote_argv = [*remote_privilege, "env", "LC_ALL=C", "timeout", "-s", "INT", "-k", "5", guard,
                           *tcpdump, args.remote_interface, "-w", "-", remote_filter]
            # Open output before tcpdump drops privileges. Avoid -Z root, which crashes
            # with -w in some Ubuntu/Debian tcpdump packages (upstream issue #1103).
            remote_script = (f"umask 077; echo $$ > {remote_pid}; "
                             f"exec {shlex.join(remote_argv)} > {shlex.quote(remote_pcap)}")
            remote_log = output / "server-tcpdump.log"
            remote_capture = subprocess.Popen(remote_command(["sh", "-c", remote_script]),
                                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                              stderr=stack.enter_context(remote_log.open("wb")),
                                              start_new_session=True)
            captures = [(local_capture, local_log), (remote_capture, remote_log)]
            wait_for_captures(captures)
            metadata["capture_ready_epoch"] = time.time()
            deadline = time.monotonic() + args.duration
            print("Both captures are ready. " + ("Reproduce the issue now; Ctrl+C saves the capture."
                                                if args.manual else "Starting independent SSH attempts."), flush=True)
            if args.manual:
                while time.monotonic() < deadline:
                    check_captures(captures)
                    time.sleep(0.2)
            else:
                test_command = [*common, "-vvv", "-oControlPath=none", "-oControlMaster=no"]
                if args.ip_qos is not None:
                    test_command.append("-oIPQoS=" + args.ip_qos)
                test_command.extend([args.host, "true"])
                for attempt in range(1, args.attempts + 1):
                    check_captures(captures)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        warn("capture window exhausted; remaining SSH attempts skipped")
                        break
                    result = ssh_attempt(test_command, output / f"ssh-{attempt:02d}.log",
                                         min(args.connect_timeout + 5, remaining))
                    metadata["attempts"].append(result)
                    print(f"Attempt {attempt}: exit={result['exit_code']}, {result['elapsed_seconds']:.3f}s",
                          flush=True)
                    if result["exit_code"] != 0:
                        status = 1
                    if attempt < args.attempts:
                        time.sleep(max(0, min(1, deadline - time.monotonic())))
                check_captures(captures)
                time.sleep(max(0, min(1, deadline - time.monotonic())))
                check_captures(captures)
        except KeyboardInterrupt:
            status = 130
            print("Stopping and saving captures...", flush=True)
        except (OSError, ValueError, RuntimeError, StopIteration, subprocess.SubprocessError) as error:
            status = 1
            warn(str(error))
            if isinstance(error, subprocess.CalledProcessError) and error.stderr:
                detail = error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else error.stderr
                warn(detail.strip())
        finally:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            if control_process and not metadata.get("control_connection_ready"):
                # Include the client's timeout/abort packets in the local capture.
                stop_ssh(control_process)
                time.sleep(0.2)
            try:
                stop_process(local_capture, privilege)
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                status = 1
                warn(f"local capture cleanup: {error}")
            if remote_dir:
                remote_stopped = False
                if remote_capture:
                    try:
                        pid_path = shlex.quote(remote_dir + "/capture.pid")
                        kill_command = shlex.join([*remote_privilege, "kill", "-INT"])
                        probe_command = shlex.join([*remote_privilege, "kill", "-0"])
                        stop_script = f"""
for attempt in 1 2 3 4 5; do
    [ ! -s {pid_path} ] || break
    sleep 0.2
done
[ -s {pid_path} ] || exit 1
capture_pid=$(cat {pid_path})
case "$capture_pid" in ''|*[!0-9]*) exit 1;; esac
if {probe_command} "$capture_pid" 2>/dev/null; then
    {kill_command} "$capture_pid" || exit 1
fi
attempt=0
while [ "$attempt" -lt 30 ]; do
    {probe_command} "$capture_pid" 2>/dev/null || exit 0
    sleep 0.2
    attempt=$((attempt + 1))
done
exit 1
"""
                        remote(["sh", "-c", stop_script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        remote_stopped = True
                    except (OSError, subprocess.SubprocessError) as error:
                        status = 1
                        warn(f"remote stop request failed (watchdog remains active): {error}")
                if remote_capture:
                    try:
                        remote_capture.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        status = 1
                        warn(f"server capture channel did not close; files retained at {remote_dir}")
                        try:
                            stop_process(remote_capture)
                        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                            warn(f"capture channel cleanup failed: {error}")
                if remote_stopped:
                    try:
                        available = remote(["test", "-s", remote_dir + "/server.pcap"], check=False,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                        if available.returncode == 0:
                            with (output / "server.pcap.part").open("wb") as capture:
                                remote(["cat", remote_dir + "/server.pcap"], stdout=capture, stderr=subprocess.PIPE)
                            validate_pcap(output / "server.pcap.part")
                            (output / "server.pcap.part").replace(output / "server.pcap")
                            server_pcap_saved = True
                        elif available.returncode != 1:
                            available.check_returncode()
                    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                        status = 1
                        warn(f"server PCAP download failed; files retained at {remote_dir}: {error}")
                try:
                    with (output / "sshd.log").open("wb") as journal:
                        remote([*remote_privilege, "journalctl", "-u", "ssh", "-u", "sshd", "--no-pager",
                                "-o", "short-unix", "--since", "@" + str(math.floor(float(remote_epoch)))],
                               stdout=journal, stderr=stack.enter_context((output / "journal-error.log").open("wb")))
                except (OSError, subprocess.SubprocessError) as error:
                    warn(f"sshd journal unavailable: {error}")
                if server_pcap_saved or remote_capture is None:
                    try:
                        if server_pcap_saved:
                            remote(["rm", "--", remote_dir + "/server.pcap", remote_dir + "/capture.pid"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                        remote(["rmdir", "--", remote_dir], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    except (OSError, subprocess.SubprocessError) as error:
                        warn(f"remote temporary directory cleanup failed: {error}")
            try:
                if Path(control_path).exists():
                    run([*control, "-O", "exit", args.host], timeout=3,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (OSError, subprocess.SubprocessError) as error:
                warn(f"control connection cleanup failed: {error}")
            stop_ssh(control_process)
            if local_ready:
                try:
                    validate_pcap(output / "client.pcap")
                except (OSError, RuntimeError) as error:
                    status = 1
                    warn(str(error))
            metadata["capture_exit_codes"] = dict(client=local_capture.poll() if local_capture else None,
                                                   server=remote_capture.poll() if remote_capture else None)
            if control_process:
                metadata["control_exit_code"] = control_process.poll()
            metadata.update(finish_epoch=time.time(), exit_code=status)
            (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Saved: {output}", flush=True)
    return status


if __name__ == "__main__":
    sys.exit(main())
