# proxy_over_ssh

A **C++23 SSH-based asynchronous proxy** built on **libssh2 + OpenSSL** using coroutines and epoll.
The proxy accepts **SOCKS5** and **HTTP/1.1 CONNECT** clients on one local port and forwards traffic through SSH
`direct-tcpip` channels. The protocol is detected automatically for each connection.

---

## Features

- **SOCKS5 and HTTP CONNECT proxy** with support for domain names, IPv4, and IPv6
- **SSH tunneling** via `direct-tcpip` channels
- **Async I/O** using C++20/23 coroutines with custom epoll scheduler
- **Transport-agnostic architecture** - proxy is decoupled from backend implementation
- **Static linking** - OpenSSL and libssh2 built from source

---

## Requirements

### Linux
- GCC ≥ 11 or Clang ≥ 14 (C++23 support required)
- make or ninja

### Android
- Android NDK
- CMake toolchain from NDK
- Supported ABIs: `arm64-v8a`, `armeabi-v7a`, `x86_64`

---

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The local `coro_lite` repository must exist at `/home/vadim/CLionProjects/coro_lite`. Initialize the submodule before
configuring the proxy:

```bash
git -c protocol.file.allow=always submodule update --init --recursive
```

See [`coro_lite`](third_party/coro_lite/README.md) for runtime integration, API, and standalone test instructions.

---

## Usage

```bash
# Using private key file
./proxy_over_ssh \
  --ssh-user USER \
  --ssh-host IP_ADDRESS \
  --ssh-port 22 \
  --ssh-host-key-sha256 SHA256:VERIFIED_FINGERPRINT \
  --ssh-private-key-path ~/.ssh/id_rsa \
  --listen-port 1080

# Using private key from environment variable
export PROXY_PRIVATE_KEY="your_base64_key_content"
./proxy_over_ssh \
  --ssh-user USER \
  --ssh-host IP_ADDRESS \
  --ssh-port 22 \
  --ssh-host-key-sha256 SHA256:VERIFIED_FINGERPRINT \
  --ssh-private-key ${PROXY_PRIVATE_KEY} \
  --listen-port 1080
```

### Command Line Options

| Option                   | Description                                                                               |
|--------------------------|-------------------------------------------------------------------------------------------|
| `--ssh-user`             | SSH username                                                                              |
| `--ssh-host`             | SSH server IP address                                                                     |
| `--ssh-port`             | SSH server port                                                                           |
| `--ssh-host-key-sha256`  | Required OpenSSH SHA-256 host-key fingerprint                                             |
| `--ssh-private-key-path` | Path to private key file                                                                  |
| `--ssh-private-key`      | Private key content (supports `\n` for newlines and `$ENV_VAR` for environment variables) |
| `--listen-port`          | Shared local SOCKS5 and HTTP CONNECT proxy port                                           |
| `--byedpi-args`          | Enable embedded ByeDPI with the supplied argument string                                  |

### Embedded ByeDPI

ByeDPI can process the SSH transport inside the proxy process, on Linux and Android:

```text
SOCKS5 / HTTP CONNECT client → proxy → embedded ByeDPI → SSH server → destination
```

On Linux, add `--byedpi-args` to the usual SSH options:

```bash
./build/proxy_over_ssh \
  --ssh-user USER --ssh-host IP_ADDRESS --ssh-port 22 \
  --ssh-host-key-sha256 SHA256:VERIFIED_FINGERPRINT \
  --ssh-private-key-path ~/.ssh/id_rsa --listen-port 1080 \
  --byedpi-args '--oob 1 -s 2 -M h,d -A torst -T 3 -f -1 -r 3+s -S --auto=none'
```

On Android, enable **Settings → ByeDPI** and edit **ByeDPI arguments** before starting the proxy.
The example above is prefilled. Existing installations keep ByeDPI disabled until enabled.

ByeDPI runs in its own thread with an automatically assigned loopback port. No `ciadpi`, `ncat`, child
process or SSH-server changes are needed. libssh2 performs SOCKS5 CONNECT to the configured SSH IP
before its normal handshake and mandatory host-key check. Android protects ByeDPI's outgoing
sockets with `VpnService.protect()` in VPN mode. Initialization or CONNECT failures fail the
connection without falling back to direct SSH.

The argument string supports quotes and backslash escaping, with no shell or environment expansion.
Single quotes preserve their contents literally. Inside double quotes, sequences such as `\n`, `\r`
and `\xNN` reach ByeDPI unchanged; backslash escapes only `"`, `\`, `$`, a backtick or a newline.
A backslash followed by a newline continues the line outside single quotes. Empty quotes produce
an empty argument. For example, `--oob-data "\n"` selects the newline byte, and
`--fake-data ":GET /\r\n\r\n"` preserves CRLF in the fake payload.
Do not supply listening, daemon, PID-file, transparent-mode, protect-path or connect-to options;
the application controls these. One embedded ByeDPI instance is supported per process.
Its worker blocks SIGPIPE before processing connections, including fake-packet splice operations,
without changing the process's signal handler or the calling thread's signal mask.
HTTP/TLS-specific manipulations apply only when ByeDPI recognizes those protocols; the forwarded
transport here is SSH. TCP strategies and their effectiveness depend on the network and kernel.
Offsets using `+s` require TLS SNI and do not split SSH data at those positions; `-A s` is a
TLS-error trigger, and `-a` applies to UDP. Use TCP byte offsets when testing an SSH strategy.
For Android diagnostics, include both `SSHProxy` and `ByeDPI` Logcat tags. Adding `-x 1` to
ByeDPI arguments enables its connection/strategy messages (`-x 2` adds verbose I/O logs).
SSH logs distinguish TCP connection, ByeDPI CONNECT and SSH handshake, and report a server's
disconnect reason when the server sends one.
Fatal ByeDPI event-loop failures stop the proxy: the CLI exits with status 1, and Android reports
an error and closes its proxy/VPN. A normal stop does not report a ByeDPI failure.
`--cache-file` caches are saved when the event loop stops, including after a fatal failure.
Malformed cache records are skipped; cache write failures are logged without preventing shutdown.

The vendored version, license and local embedding patches are documented in
[`third_party/byedpi/UPSTREAM.md`](third_party/byedpi/UPSTREAM.md). Include its MIT license when distributing binaries.

Run the Debug tests with:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DPROXY_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

The SOCKS5 and runtime tests exercise fragmented replies, SSH-banner preservation, concurrent data
transfers, socket protection and repeated startup/shutdown. `byedpi_arguments` verifies quoting
and the exact bytes produced by ByeDPI's native converters. `byedpi_sigpipe` checks send/splice
on a closed socket with the default signal handler; `byedpi_signal_startup` checks cleanup and
retry after a signal-mask setup failure. The optional `byedpi_ssh` test needs
Python's `paramiko` package and starts a local SSH fixture with temporary keys. It verifies real
libssh2 authentication, both client protocols and rejection of an incorrect host-key fingerprint.

### Start an Android profile from ADB

Pass the saved profile's exact, case-sensitive name as the `profile_name` activity extra:

```bash
adb shell 'am start -W -n io.sshproxy.app/.MainActivity --es profile_name "Profile name"'
```

This selects the profile and starts the normal proxy/VPN flow without pressing Start. It works
for a cold launch and for an already open activity. Initial Android VPN consent must still be
granted by the user; later launches run automatically while that permission remains valid.
The optional notification-permission prompt is skipped for explicit automation starts.
The profile ID is retained while awaiting VPN consent, and the launch extra is consumed once.

Missing, blank and duplicate names produce an error in the app and in Logcat under `MainActivity`.
Repeating the command for the active profile leaves it running. An active different profile must
be stopped first. No SSH credentials are passed through ADB. To reset the app between automated runs:

```bash
adb shell am force-stop io.sshproxy.app
adb shell 'am start -W -n io.sshproxy.app/.MainActivity --es profile_name "Profile name"'
adb logcat -s MainActivity SSHProxy ByeDPI
```

`am start -W` waits for the activity launch; proxy startup is confirmed by its status/log messages.

Profile-launch instrumented tests use a separate app ID so they cannot replace saved user profiles:

```bash
cd android/ProxyApp
JAVA_HOME=/home/vadim/android-studio/jbr ./gradlew connectedDebugAndroidTest \
  -PprofileTestApplicationId=io.sshproxy.app.autostarttest
```

The profile-launch tests require Android 12/API 31 or later and invoke `am start` through the shell.
They use placeholder keys and a local SOCKS listener with VPN disabled. Rebuild without this
property to produce the regular `io.sshproxy.app` APK.

### Obtain the SSH host-key fingerprint

The safest source is the SSH server itself. Run this on the server to print its ECDSA host-key fingerprint:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub -E sha256
```

To display every configured host key, run:

```bash
for key in /etc/ssh/ssh_host_*_key.pub; do
  sudo ssh-keygen -lf "$key" -E sha256
done
```

Copy the complete `SHA256:...` value into `--ssh-host-key-sha256`. If server access is unavailable, retrieve the
advertised keys with `ssh-keyscan -p PORT HOST | ssh-keygen -lf - -E sha256`, but verify the result through the
hosting console or administrator. A fingerprint learned only from the connection being protected does not prevent a
first-connection man-in-the-middle attack.

### Test with curl

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me

# HTTP/1.1 CONNECT (used automatically for this HTTPS URL)
curl --proxy http://127.0.0.1:1080 https://ifconfig.me
```

The HTTP endpoint supports tunneling with `CONNECT` only. It does not implement ordinary HTTP request forwarding or
proxy authentication.

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│ SOCKS5/HTTP │────▶│   Backend   │
│  (curl)     │     │CONNECT Proxy│     │  (SshSocket)│
└─────────────┘     └─────────────┘     └─────────────┘
                          │                    │
                          │                    ▼
                    BackendFactory      ┌─────────────┐
                    (interface)         │  SSH Server │
                                        └─────────────┘
```

The proxy uses a **factory pattern** to create backend connections, making it transport-agnostic. The `IBackendSocket` interface allows different backend implementations (SSH, direct TCP, etc.).

---

## Systemd Service

```bash
sudo cp systemd/proxy_over_ssh.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable proxy_over_ssh
sudo systemctl start proxy_over_ssh
```

---

## Project Structure

```
├── main.cpp           # Entry point, config parsing, factory creation
├── SSHProxy.h/cpp     # Protocol detection and proxy connection lifecycle
├── HttpConnect.h/cpp  # HTTP/1.1 CONNECT parsing and responses
├── BackendSocket.h    # Abstract interface for backend connections
├── SshSocket.h/cpp    # SSH tunneling implementation
├── Types.h            # Common types (ResultCode, Socks5 constants)
├── third_party/
│   └── coro_lite/     # Coroutine scheduler, sockets, cancellation, timers, and endpoints
├── android/ProxyApp/  # Android VPN application and JNI integration
└── systemd/           # Systemd service file
```
