# proxy_over_ssh

A **C++ SSH-based asynchronous (epoll/event-driven)** proxy application built on
**libssh2 + OpenSSL**.  
The proxy exposes a local **SOCKS5** server and forwards traffic through an
SSH connection using `direct-tcpip` channels.

---

## Requirements

### Linux
- GCC ≥ 11 or Clang ≥ 14
- make or ninja

### Android
- Android NDK
- CMake toolchain from NDK
- Supported ABIs:
  - `arm64-v8a`
  - `armeabi-v7a`
  - `x86_64`

---

## Dependencies

All dependencies are downloaded and built automatically via **CPM.cmake**.

### OpenSSL
- Static build
- No system OpenSSL dependency

### libssh2
- Version 1.11.1
- OpenSSL crypto backend
- Static build

---

## Build (Linux)

```bash
git clone <repo>
cd proxy_over_ssh

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Run Example
``` bash
./proxy_over_ssh \
  --ssh-user USER \
  --ssh-host IP_ADDRESS \
  --ssh-port PORT \
  --ssh-key ~/.ssh/id_rsa \
  --listen-port LOCAL_PORT
```

## Systemd
``` bash
sudo cp proxy_over_ssh.service ${HOME}/.config/systemd/user/
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable proxy_over_ssh
sudo systemctl start proxy_over_ssh
```