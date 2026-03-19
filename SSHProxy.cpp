//
// Created by vadim on 31.10.2025.
//

#include "SSHProxy.h"

#include <iostream>
#include <unistd.h>
#include <cstring>
#include <expected>
#include <format>
#include <thread>
#include <utility>
#include <vector>
#include <ranges>
#include <span>
#include <string>
#include <limits>
#include <chrono>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <libssh2.h>

#include "CoroTask.h"
#include "Socket.h"
#include "SshSocket.h"

// SOCKS Protocol Version 5 Documentation
// https://datatracker.ietf.org/doc/html/rfc1928

constexpr int BUFFER_SIZE = 2 * 8192;
constexpr bool PRINT_VERBOSE_LOG = true;

template<typename... Args>
void log_d(std::format_string<Args...> fmt, Args &&... args) {
    std::cout << std::format(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
void log_v(std::format_string<Args...> fmt, Args &&... args) {
    if (PRINT_VERBOSE_LOG) {
        log_d(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
void log_e(std::format_string<Args...> fmt, Args &&... args) {
    std::cerr << std::format(fmt, std::forward<Args>(args)...);
}

namespace Socks5 {
    constexpr int Version = 0x5;

    namespace Cmd {
        constexpr int Connect = 0x1;
    }

    namespace Auth {
        constexpr int NoAuth = 0x0;
    }

    namespace Atyp {
        constexpr int IpV4 = 0x1;
        constexpr int Domain = 0x3;
        constexpr int IpV6 = 0x4;
    }

    namespace Rep {
        constexpr int Success = 0x00;
        constexpr int GeneralFailure = 0x01;
        constexpr int ConnectionNotAllowed = 0x02;
        constexpr int NetworkUnreachable = 0x03;
        constexpr int HostUnreachable = 0x04;
        constexpr int ConnectionRefused = 0x05;
        constexpr int TtlExpired = 0x06;
        constexpr int CommandNotSupported = 0x07;
        constexpr int AddressTypeNotSupported = 0x08;
    }
} // namespace Socks5

struct ClientContextCoro final {
    enum class State {
        HANDSHAKE,
        REQUEST,
        SSH_SOCKET_CONNECT,
        FORWARDING,
        CLOSED
    };

    ClientContextCoro(Endpoint endpoint_, SocketPtr socket_)
        : endpoint(std::move(endpoint_)),
          socket(std::move(socket_)) {
    }

    ClientContextCoro(const ClientContextCoro &) = delete;

    ClientContextCoro &operator=(const ClientContextCoro &) = delete;

    ClientContextCoro(ClientContextCoro &&) = default;

    ClientContextCoro &operator=(ClientContextCoro &&) = default;

    ~ClientContextCoro() = default;

    [[nodiscard]] bool isConnected() const noexcept {
        return socket && socket->fd() != -1;
    }

    void closeSocket() noexcept {
        if (socket) {
            socket->close();
        }
    }

    void setState(const State newState) noexcept {
        state = newState;
    }

    [[nodiscard]] State getState() const noexcept {
        return state;
    }

    [[nodiscard]] bool isState(const State state_) const noexcept {
        return state == state_;
    }

    Endpoint endpoint;
    Endpoint targetEndpoint;
    SocketPtr socket;
    std::vector<uint8_t> buffer;

private:
    State state = State::HANDSHAKE;
};

namespace {
    constexpr size_t safeAdd(const size_t a, const size_t b) {
        if (a > std::numeric_limits<size_t>::max() - b) {
            throw std::runtime_error("Integer overflow in size calculation");
        }
        return a + b;
    }

    CoroTask<void> readUntil(const std::shared_ptr<ClientContextCoro> clientCtx,
                             const size_t totalSize) {
        if (clientCtx->buffer.size() < totalSize) {
            throw std::runtime_error("Buffer too small for requested read size");
        }

        size_t totalRead = 0;
        while (totalRead < totalSize) {
            const size_t remaining = clientCtx->buffer.size() - totalRead;
            const size_t read = co_await clientCtx->socket->read({
                clientCtx->buffer.data() + totalRead,
                remaining
            });
            if (read == 0) {
                throw std::runtime_error("Connection closed during read");
            }
            if (read > remaining) {
                throw std::runtime_error("Socket read overflow");
            }
            totalRead = safeAdd(totalRead, read);
        }
    }
}


// SOCKS5 negotiation header (RFC 1928)
//+----+----------+----------+
//|VER | NMETHODS | METHODS  |
//+----+----------+----------+
//| 1  |    1     | 1 to 255 |
//+----+----------+----------+
struct Socks5Negotiation final {
    static constexpr uint8_t kMaxMethods = 16;

    uint8_t version = {};
    uint8_t nmethodLength = {};
    std::span<const uint8_t> nmethodsData;


    static CoroTask<Socks5Negotiation> parse(const std::shared_ptr<ClientContextCoro> clientCtx) {
        Socks5Negotiation result;

        constexpr size_t kHeaderSize = 2;
        clientCtx->buffer.resize(kHeaderSize);
        co_await readUntil(clientCtx, kHeaderSize);

        result.version = clientCtx->buffer[0];
        result.nmethodLength = clientCtx->buffer[1];

        if (result.version != Socks5::Version) {
            throw std::runtime_error("SOCKS5 version mismatch");
        }

        if (result.nmethodLength == 0) {
            result.nmethodsData = {};
            co_return result;
        }

        if (result.nmethodLength > kMaxMethods) {
            throw std::runtime_error("SOCKS5 handshake: too many authentication methods");
        }

        clientCtx->buffer.resize(result.nmethodLength);
        co_await readUntil(clientCtx, result.nmethodLength);
        result.nmethodsData = {clientCtx->buffer.data(), result.nmethodLength};
        co_return result;
    }
};

CoroTask<void> handleSocks5Handshake(const std::shared_ptr<ClientContextCoro> clientCtx) {
    const auto negotiation = co_await Socks5Negotiation::parse(clientCtx);

    const bool hasNoAuth = std::ranges::find_if(negotiation.nmethodsData, [](const auto c) {
        return c == Socks5::Auth::NoAuth;
    }) != negotiation.nmethodsData.end();

    const uint8_t selectedMethod = hasNoAuth ? Socks5::Auth::NoAuth : 0xFF;

    clientCtx->buffer.resize(2);
    clientCtx->buffer[0] = Socks5::Version;
    clientCtx->buffer[1] = selectedMethod;
    const size_t length = co_await clientCtx->socket->write({clientCtx->buffer.data(), clientCtx->buffer.size()});
    if (length != clientCtx->buffer.size()) {
        throw std::runtime_error("Failed to write to client");
    }

    if (selectedMethod == 0xFF) {
        throw std::runtime_error("No acceptable SOCKS5 authentication method");
    }

    clientCtx->setState(ClientContextCoro::State::REQUEST);
}

static CoroTask<void> writeAll(const SocketPtr &socket, std::span<const uint8_t> data) {
    size_t offset = 0;
    while (offset < data.size()) {
        const size_t written = co_await socket->write({
            const_cast<uint8_t *>(data.data()) + offset,
            data.size() - offset
        });
        if (written == 0) {
            throw std::runtime_error("Socket closed during write");
        }
        offset += written;
    }
    co_return;
}

// SOCKS5 request header (RFC 1928)
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  |   1   |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
struct Socks5Request final {
    static constexpr size_t kHeaderSize = 4;

    uint8_t version;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
    Endpoint targetEndpoint;

    static CoroTask<Socks5Request> readRequest(const std::shared_ptr<ClientContextCoro> clientCtx) {
        auto readBytes = [&clientCtx](auto &buffer, size_t &offset, const size_t n) -> CoroTask<void> {
            buffer.resize(offset + n);
            while (offset < buffer.size()) {
                const size_t read = co_await clientCtx->socket->read({buffer.data() + offset, buffer.size() - offset});
                if (read == 0) {
                    throw std::runtime_error("Socket closed during SOCKS5 request");
                }
                offset += read;
            }
        };

        size_t offset = 0;

        co_await readBytes(clientCtx->buffer, offset, kHeaderSize);

        const uint8_t version = clientCtx->buffer[0];
        const uint8_t cmd = clientCtx->buffer[1];
        const uint8_t rsv = clientCtx->buffer[2];
        const uint8_t atyp = clientCtx->buffer[3];

        if (rsv != 0) {
            throw std::runtime_error("Invalid SOCKS5 request: RSV must be 0");
        }
        if (version != Socks5::Version || cmd != Socks5::Cmd::Connect) {
            throw std::runtime_error("Unsupported SOCKS5 version or command");
        }

        Endpoint targetEndpoint;
        switch (atyp) {
            case Socks5::Atyp::IpV4: {
                co_await readBytes(clientCtx->buffer, offset, 6);
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                std::memcpy(&addr.sin_addr, &clientCtx->buffer[4], sizeof(in_addr));
                addr.sin_port = htons(static_cast<uint16_t>(clientCtx->buffer[8] << 8) | clientCtx->buffer[9]);
                targetEndpoint = Endpoint(addr);
                break;
            }

            case Socks5::Atyp::Domain: {
                co_await readBytes(clientCtx->buffer, offset, 1);
                const uint8_t domainLen = clientCtx->buffer[4];
                co_await readBytes(clientCtx->buffer, offset, domainLen + 2);
                std::string targetHost = std::string(reinterpret_cast<const char *>(&clientCtx->buffer[5]), domainLen);
                uint16_t targetPort = static_cast<uint16_t>(clientCtx->buffer[5 + domainLen] << 8) |
                                      clientCtx->buffer[5 + domainLen + 1];
                targetEndpoint = Endpoint(targetHost, targetPort);
                break;
            }

            case Socks5::Atyp::IpV6: {
                co_await readBytes(clientCtx->buffer, offset, 18);
                sockaddr_in6 addr6{};
                addr6.sin6_family = AF_INET6;
                std::memcpy(&addr6.sin6_addr, &clientCtx->buffer[4], sizeof(in6_addr));
                addr6.sin6_port = htons(static_cast<uint16_t>(clientCtx->buffer[20] << 8) | clientCtx->buffer[21]);
                targetEndpoint = Endpoint(addr6);
                break;
            }

            default:
                throw std::runtime_error("Unsupported SOCKS5 address type");
        }

        co_return Socks5Request{
            .version = version,
            .cmd = cmd,
            .rsv = rsv,
            .atyp = atyp,
            .targetEndpoint = targetEndpoint
        };
    }
};

// SOCKS5 response header (RFC 1928)
// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  |   1   |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
struct Socks5Response final {
    static constexpr size_t kHeaderSize = 4;

    uint8_t version = Socks5::Version;
    uint8_t rep = Socks5::Rep::Success;
    uint8_t rsv = 0;
    uint8_t atyp = Socks5::Atyp::IpV4;
    std::vector<uint8_t> bndAddr;
    uint16_t bndPort = 0;

    Socks5Response() = default;

    static Socks5Response ipv4(uint32_t addr, uint16_t port) {
        Socks5Response resp;
        resp.atyp = Socks5::Atyp::IpV4;
        resp.bndAddr.resize(4);
        resp.bndAddr[0] = static_cast<uint8_t>((addr >> 24) & 0xFF);
        resp.bndAddr[1] = static_cast<uint8_t>((addr >> 16) & 0xFF);
        resp.bndAddr[2] = static_cast<uint8_t>((addr >> 8) & 0xFF);
        resp.bndAddr[3] = static_cast<uint8_t>(addr & 0xFF);
        resp.bndPort = port;
        return resp;
    }

    static Socks5Response ipv6(const uint8_t addr[16], uint16_t port) {
        Socks5Response resp;
        resp.atyp = Socks5::Atyp::IpV6;
        resp.bndAddr.assign(addr, addr + 16);
        resp.bndPort = port;
        return resp;
    }

    static Socks5Response domain(const std::string &domain, uint16_t port) {
        Socks5Response resp;
        resp.atyp = Socks5::Atyp::Domain;
        resp.bndAddr.resize(1 + domain.size());
        resp.bndAddr[0] = static_cast<uint8_t>(domain.size());
        std::memcpy(resp.bndAddr.data() + 1, domain.data(), domain.size());
        resp.bndPort = port;
        return resp;
    }

    static Socks5Response ipv4Any(const uint16_t port) {
        return ipv4(0, port);
    }

    static Socks5Response fromHost(const std::string &host, uint16_t port) {
        sockaddr_in6 sa6{};
        sockaddr_in sa{};

        if (inet_pton(AF_INET6, host.c_str(), &sa6.sin6_addr) == 1) {
            uint8_t addr[16];
            std::memcpy(addr, &sa6.sin6_addr, 16);
            return ipv6(addr, port);
        }
        if (inet_pton(AF_INET, host.c_str(), &sa.sin_addr) == 1) {
            const uint32_t addr = ntohl(sa.sin_addr.s_addr);
            return ipv4(addr, port);
        }
        return domain(host, port);
    }

    [[nodiscard]] size_t size() const {
        return kHeaderSize + bndAddr.size() + 2;
    }

    void serialize(std::span<uint8_t> buffer) const {
        if (buffer.empty()) {
            return;
        }
        buffer[0] = version;
        buffer[1] = rep;
        buffer[2] = rsv;
        buffer[3] = atyp;
        std::memcpy(buffer.data() + kHeaderSize, bndAddr.data(), bndAddr.size());
        const size_t portOffset = kHeaderSize + bndAddr.size();
        buffer[portOffset] = static_cast<uint8_t>(bndPort >> 8);
        buffer[portOffset + 1] = static_cast<uint8_t>(bndPort & 0xFF);
    }

    [[nodiscard]] std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> result(size());
        serialize(result);
        return result;
    }

    void serializeTo(std::vector<uint8_t> &buffer) const {
        buffer.resize(size());
        serialize(buffer);
    }
};

CoroTask<void> handleSocks5Request(const std::shared_ptr<ClientContextCoro> clientCtx) {
    const auto req = co_await Socks5Request::readRequest(clientCtx);
    clientCtx->targetEndpoint = req.targetEndpoint;

    clientCtx->setState(ClientContextCoro::State::SSH_SOCKET_CONNECT);
}

static CoroTask<void> sendSocks5Success(const std::shared_ptr<ClientContextCoro> clientCtx) {
    Socks5Response::ipv4Any(clientCtx->targetEndpoint.port()).serializeTo(clientCtx->buffer);
    co_await writeAll(clientCtx->socket, {clientCtx->buffer.data(), clientCtx->buffer.size()});
}

static void sendSocks5FailureSync(const std::shared_ptr<ClientContextCoro> clientCtx,
                                  uint8_t errorCode = Socks5::Rep::GeneralFailure) {
    Socks5Response response;
    response.rep = errorCode;
    response.atyp = Socks5::Atyp::IpV4;
    response.bndAddr = {0, 0, 0, 0};
    response.bndPort = 0;

    std::vector<uint8_t> buffer;
    response.serializeTo(buffer);

    if (const int fd = clientCtx->socket->fd(); fd >= 0) {
        send(fd, buffer.data(), buffer.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
    }
}

struct ForwardState {
    std::atomic<bool> clientDone{false};
    std::atomic<bool> sshDone{false};
    std::shared_ptr<ClientContextCoro> client;
    std::shared_ptr<SshSocket> ssh;
};

static CoroTask<void> forwardClientToSsh(std::shared_ptr<ForwardState> state) {
    constexpr size_t kBufferSize = 8192;
    std::vector<uint8_t> buffer(kBufferSize);

    while (!state->clientDone.load() && !state->sshDone.load()) {
        if (state->client->socket->isEof()) {
            break;
        }

        const size_t n = co_await state->client->socket->read(buffer);
        if (n == 0) {
            if (state->client->socket->isEof()) {
                break;
            }
            continue;
        }

        size_t written = 0;
        while (written < n && !state->sshDone.load()) {
            if (state->ssh->isEof()) {
                state->sshDone.store(true);
                break;
            }
            const size_t chunk = co_await state->ssh->write({buffer.data() + written, n - written});
            if (chunk == 0 && state->ssh->isEof()) {
                state->sshDone.store(true);
                break;
            }
            written += chunk;
        }
    }

    state->clientDone.store(true);
    state->ssh->close();
}

static CoroTask<void> forwardSshToClient(std::shared_ptr<ForwardState> state) {
    constexpr size_t kBufferSize = 8192;
    std::vector<uint8_t> buffer(kBufferSize);

    while (!state->sshDone.load() && !state->clientDone.load()) {
        if (state->ssh->isEof()) {
            break;
        }

        const size_t n = co_await state->ssh->read(buffer);
        if (n == 0) {
            if (state->ssh->isEof()) {
                break;
            }
            continue;
        }

        try {
            co_await writeAll(state->client->socket, {buffer.data(), n});
        } catch (const std::runtime_error &) {
            state->clientDone.store(true);
            break;
        }
    }

    state->sshDone.store(true);
    state->client->closeSocket();
}

static CoroTask<void> forwardData(const std::shared_ptr<ClientContextCoro> clientCtx,
                                  const std::shared_ptr<SshSocket> sshSocket) {
    clientCtx->setState(ClientContextCoro::State::FORWARDING);

    const auto state = std::make_shared<ForwardState>();
    state->client = clientCtx;
    state->ssh = sshSocket;

    auto *scheduler = co_await GetScheduler{};

    auto clientToSsh = forwardClientToSsh(state);
    auto sshToClient = forwardSshToClient(state);

    clientToSsh.detach(*scheduler);
    sshToClient.detach(*scheduler);

    const auto startTime = std::chrono::steady_clock::now();
    constexpr auto timeout = std::chrono::seconds(30);

    while (!state->clientDone.load() || !state->sshDone.load()) {
        if (std::chrono::steady_clock::now() - startTime > timeout) {
            state->clientDone.store(true);
            state->sshDone.store(true);
            shutdown(clientCtx->socket->fd(), SHUT_RDWR);
            shutdown(sshSocket->fd(), SHUT_RDWR);
            break;
        }
        co_await TimerAwaiter{std::chrono::milliseconds{100}};
    }

    clientCtx->setState(ClientContextCoro::State::CLOSED);
}

static CoroTask<void> handleClient(SSHConfig sshConfig,
                                   Endpoint endpoint,
                                   SocketPtr socket) {
    const auto client = std::make_shared<ClientContextCoro>(endpoint, socket);
    try {
        co_await handleSocks5Handshake(client);
        co_await handleSocks5Request(client);

        const auto sshSocket = std::make_shared<SshSocket>(sshConfig);
        if (const auto connectResult = co_await sshSocket->connectAsync(client->targetEndpoint);
            connectResult != ResultCode::Ok) {
            sendSocks5FailureSync(client);
            client->closeSocket();
            co_return;
        }

        co_await sendSocks5Success(client);
        co_await forwardData(client, sshSocket);
    } catch (const std::exception &) {
        sendSocks5FailureSync(client);
    } catch (...) {
        sendSocks5FailureSync(client);
    }
    client->closeSocket();
}

CoroTask<void> startMainLoop(const ProxyConfig config) {
    Socket serverSocket;
    serverSocket.setReusePort(true);
    std::cout << "listen port: " << config.listenPort << '\n';
    if (!serverSocket.bind(Endpoint(config.listenPort))) {
        throw std::runtime_error("Failed to bind server socket");
    }

    auto *scheduler = co_await GetScheduler{};

    while (true) {
        auto [socket, endpoint] = co_await serverSocket.listen();
        std::cout << "new socket ip: " << endpoint.ipStr() << ", port: " << endpoint.port() << '\n';

        auto handler = handleClient(config.ssh, endpoint, socket);
        handler.detach(*scheduler);
    }
}

SSHProxy::SSHProxy(const std::atomic_bool &stopSignalFlag_) : stopSignalFlag(stopSignalFlag_) {
    libssh2_init(0);
}

SSHProxy::~SSHProxy() {
    requestStop();
    libssh2_exit();
}

void SSHProxy::start(const ProxyConfig &proxyConfig) {
    if (mainThread) {
        throw std::runtime_error("Already started");
    }
    this->config = proxyConfig;
    mainThread = std::jthread(&SSHProxy::mainLoop, this);
}

void SSHProxy::requestStop() noexcept {
    if (mainThread) {
        mainThread->request_stop();
    }
}

void SSHProxy::waitForFinish() {
    if (mainThread) {
        mainThread.value().join();
    }
}

void SSHProxy::mainLoop(const std::stop_token &stopToken) {
    log_d("SOCKS5 proxy started on port: {} via SSH: {}:{}\n",
          config.value().listenPort,
          config.value().ssh.host,
          config.value().ssh.port);
    log_d("Proxy started. Press Ctrl+C to stop...\n");

    const auto isStopRequested = [stopToken, &flag = stopSignalFlag]() {
        return stopToken.stop_requested() || flag.load(std::memory_order_relaxed);
    };

    EpollScheduler sched(isStopRequested);
    const auto task = startMainLoop(config.value());
    task.start(sched);
    sched.run();
    log_d("Proxy finished\n");
}
