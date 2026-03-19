# proxy_over_ssh

A **C++23 SSH-based asynchronous proxy** built on **libssh2 + OpenSSL** using coroutines and epoll.
The proxy exposes a local **SOCKS5** server and forwards traffic through an SSH connection using `direct-tcpip` channels.

---

## Features

- **SOCKS5 proxy** with support for domain names, IPv4, and IPv6
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
  --ssh-private-key-path ~/.ssh/id_rsa \
  --listen-port 1080

# Using private key from environment variable
export PROXY_PRIVATE_KEY="your_base64_key_content"
./proxy_over_ssh \
  --ssh-user USER \
  --ssh-host IP_ADDRESS \
  --ssh-port 22 \
  --ssh-private-key ${PROXY_PRIVATE_KEY} \
  --listen-port 1080
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--ssh-user` | SSH username |
| `--ssh-host` | SSH server IP address |
| `--ssh-port` | SSH server port |
| `--ssh-private-key-path` | Path to private key file |
| `--ssh-private-key` | Private key content (supports `\n` for newlines and `$ENV_VAR` for environment variables) |
| `--listen-port` | Local SOCKS5 proxy port |

### Test with curl

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│   SOCKS5    │────▶│   Backend   │
│  (curl)     │     │   Proxy     │     │  (SshSocket)│
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
├── SSHProxy.h/cpp     # SOCKS5 proxy implementation
├── BackendSocket.h    # Abstract interface for backend connections
├── SshSocket.h/cpp    # SSH tunneling implementation
├── Socket.h/cpp       # Socket abstraction with coroutine awaiters
├── CoroTask.h         # Coroutine infrastructure (EpollScheduler, CoroTask)
├── Endpoint.h/cpp     # Network endpoint abstraction
├── Types.h            # Common types (ResultCode, Socks5 constants)
├── Logger.h           # Logging utilities
└── systemd/           # Systemd service file
```
