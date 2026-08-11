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
├── Socket.h/cpp       # Socket abstraction with coroutine awaiters
├── CoroTask.h         # Coroutine infrastructure (EpollScheduler, CoroTask)
├── Endpoint.h/cpp     # Network endpoint abstraction
├── Types.h            # Common types (ResultCode, Socks5 constants)
├── Logger.h           # Logging utilities
└── systemd/           # Systemd service file
```
