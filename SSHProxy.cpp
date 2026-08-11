//
// Created by vadim on 31.10.2025.
//

#include <chrono>
#include <exception>
#include <format>
#include <limits>
#include <mutex>
#include <ranges>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <libssh2.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include "BackendSocket.h"
#include "Buffer.h"
#include "CompletionSignal.h"
#include "Constants.h"
#include "CoroTask.h"
#include "IdleTimer.h"
#include "HttpConnect.h"
#include "Logger.h"
#include "SSHProxy.h"
#include "Socket.h"
#include "Types.h"

using namespace CoroLite;

namespace {
    enum class ClientProtocol {
        Unknown,
        Socks5,
        HttpConnect,
    };

    struct ClientContextCoro final {
        ClientContextCoro(Endpoint endpoint_, SocketPtr socket_) :
            endpoint(std::move(endpoint_)),
            socket(std::move(socket_)) {
        }

        ClientContextCoro(const ClientContextCoro &) = delete;

        ClientContextCoro &operator=(const ClientContextCoro &) = delete;

        ClientContextCoro(ClientContextCoro &&) = default;

        ClientContextCoro &operator=(ClientContextCoro &&) = default;

        ~ClientContextCoro() {
            closeSocket();
        }

        void closeSocket() noexcept {
            if (socket != nullptr) {
                socket->close();
            }
        }

        Endpoint endpoint;
        Endpoint targetEndpoint;
        SocketPtr socket;
        std::vector<uint8_t> buffer;
        std::vector<uint8_t> prefetchedClientData;
        ClientProtocol protocol = ClientProtocol::Unknown;
    };

    constexpr size_t safeAdd(const size_t a, const size_t b) {
        if (a > std::numeric_limits<size_t>::max() - b) {
            throw std::runtime_error("Integer overflow in size calculation");
        }
        return a + b;
    }

    [[nodiscard]] CoroTask<> readUntil(const std::shared_ptr<ClientContextCoro> clientCtx,
                                      const size_t totalSize,
                                      const CancellationTokenSource &setupCts,
                                      const size_t alreadyRead = 0) {
        if (clientCtx->buffer.size() < totalSize || alreadyRead > totalSize) {
            throw std::runtime_error("Buffer too small for requested read size");
        }

        size_t totalRead = alreadyRead;
        while (totalRead < totalSize) {
            const size_t remaining = totalSize - totalRead;
            const size_t read = co_await clientCtx->socket->read(
                {clientCtx->buffer.data() + totalRead, remaining},
                setupCts.getToken()
            );
            if (read == 0) {
                throw std::runtime_error("Connection closed during read");
            }
            if (read > remaining) {
                throw std::runtime_error("Socket read overflow");
            }
            totalRead = safeAdd(totalRead, read);
        }
    }

    [[nodiscard]] CoroTask<size_t> writeAll(SocketPtr socket,
                                            std::span<const uint8_t> data,
                                            CancellationTokenOpt ct);

    struct MultiFdAwaiter final : SchedulerAware<EpollScheduler> {
        struct FdInfo final {
            int fd;
            uint32_t events;
        };

        explicit MultiFdAwaiter(std::vector<FdInfo> fds_) :
            fds(std::move(fds_)) {
        }

        [[nodiscard]] bool await_ready() const noexcept {
            return false;
        }

        void await_suspend(const std::coroutine_handle<> h) {
            handle = h;
            std::vector<int> registeredFds;
            registeredFds.reserve(fds.size());
            try {
                for (const auto &[fd, events]: fds) {
                    this->getScheduler()->add(events, fd, h);
                    registeredFds.push_back(fd);
                }
            } catch (...) {
                for (const int fd: registeredFds) {
                    this->getScheduler()->rollbackAdd(fd, h);
                }
                throw;
            }
        }

        std::vector<int> await_resume() {
            for (const auto &[fd, _]: fds) {
                this->getScheduler()->rollbackAdd(fd, handle);
            }
            std::vector<int> ready;
            for (const auto &[fd, _]: fds) {
                pollfd pollFD{fd, POLLIN, 0};
                if (poll(&pollFD, 1, 0) == 1 && pollFD.revents & POLLIN) {
                    ready.push_back(fd);
                }
            }
            return ready;
        }

    private:
        std::vector<FdInfo> fds;
        std::coroutine_handle<> handle;
    };

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


    [[nodiscard]] static CoroTask<Socks5Negotiation> parse(const std::shared_ptr<ClientContextCoro> clientCtx,
                                                           const CancellationTokenSource &setupCts) {
        Socks5Negotiation result;

        constexpr size_t kHeaderSize = 2;
        clientCtx->buffer.resize(kHeaderSize);
        co_await readUntil(clientCtx, kHeaderSize, setupCts, 1);

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
        co_await readUntil(clientCtx, result.nmethodLength, setupCts);
        result.nmethodsData = {clientCtx->buffer.data(), result.nmethodLength};
        co_return result;
    }
};

[[nodiscard]] CoroTask<> handleSocks5Handshake(const std::shared_ptr<ClientContextCoro> clientCtx,
                                               const CancellationTokenSource &setupCts) {
    const auto negotiation = co_await Socks5Negotiation::parse(clientCtx, setupCts);

    const bool hasNoAuth = std::ranges::find_if(negotiation.nmethodsData, [](const auto c) {
                               return c == Socks5::Auth::NoAuth;
                           }) != negotiation.nmethodsData.end();

    const uint8_t selectedMethod = hasNoAuth ? Socks5::Auth::NoAuth : 0xFF;

    clientCtx->buffer.resize(2);
    clientCtx->buffer[0] = Socks5::Version;
    clientCtx->buffer[1] = selectedMethod;
    const size_t length = co_await writeAll(clientCtx->socket,
                                           {clientCtx->buffer.data(), clientCtx->buffer.size()},
                                           setupCts.getToken());
    if (length != clientCtx->buffer.size()) {
        throw std::runtime_error("Failed to write to client");
    }

    if (selectedMethod == 0xFF) {
        throw std::runtime_error("No acceptable SOCKS5 authentication method");
    }
}

[[nodiscard]] CoroTask<size_t> writeAll(SocketPtr socket, std::span<const uint8_t> data, CancellationTokenOpt ct) {
    size_t offset = 0;
    while (offset < data.size()) {
        CancellationTokenOpt writeToken;
        if (ct) {
            writeToken.emplace(ct->clone());
        }
        const size_t written = co_await socket->write(
            {const_cast<uint8_t *>(data.data()) + offset, data.size() - offset}, std::move(writeToken));
        if (written == 0) {
            throw std::runtime_error("Socket closed during write");
        }
        offset += written;
    }
    co_return offset;
}

[[nodiscard]] CoroTask<> detectClientProtocol(const std::shared_ptr<ClientContextCoro> clientCtx,
                                              const CancellationTokenSource &setupCts) {
    clientCtx->buffer.resize(1);
    co_await readUntil(clientCtx, 1, setupCts);
    clientCtx->protocol = clientCtx->buffer.front() == Socks5::Version ? ClientProtocol::Socks5
                                                                       : ClientProtocol::HttpConnect;
}

[[nodiscard]] CoroTask<std::expected<void, HttpConnect::Error>> readHttpConnectRequest(
    const std::shared_ptr<ClientContextCoro> clientCtx,
    const CancellationTokenSource &setupCts) {
    while (true) {
        const std::string_view request(reinterpret_cast<const char *>(clientCtx->buffer.data()),
                                       clientCtx->buffer.size());
        if (request.find("\r\n\r\n") != std::string_view::npos) {
            const auto parsed = HttpConnect::parseRequest(clientCtx->buffer);
            if (!parsed) {
                co_return std::unexpected(parsed.error());
            }
            clientCtx->targetEndpoint = parsed->target;
            clientCtx->prefetchedClientData.assign(clientCtx->buffer.begin() +
                                                        static_cast<std::ptrdiff_t>(parsed->headerSize),
                                                    clientCtx->buffer.end());
            co_return std::expected<void, HttpConnect::Error>{};
        }
        if (clientCtx->buffer.size() >= HttpConnect::MaxHeaderSize) {
            co_return std::unexpected(HttpConnect::Error{
                HttpConnect::Status::RequestHeaderFieldsTooLarge, "HTTP request headers exceed 16 KiB"});
        }

        const size_t oldSize = clientCtx->buffer.size();
        const size_t nextSize = std::min(HttpConnect::MaxHeaderSize, safeAdd(oldSize, size_t{1024}));
        clientCtx->buffer.resize(nextSize);
        const size_t bytesRead = co_await clientCtx->socket->read(
            {clientCtx->buffer.data() + oldSize, nextSize - oldSize}, setupCts.getToken());
        if (bytesRead == 0) {
            throw std::runtime_error("Connection closed during HTTP CONNECT request");
        }
        if (bytesRead > nextSize - oldSize) {
            throw std::runtime_error("Socket read overflow");
        }
        clientCtx->buffer.resize(safeAdd(oldSize, bytesRead));
    }
}

[[nodiscard]] CoroTask<> sendHttpConnectResponse(const std::shared_ptr<ClientContextCoro> clientCtx,
                                                 const HttpConnect::Status status,
                                                 CancellationTokenOpt ct) {
    const std::string_view response = HttpConnect::response(status);
    const auto *data = reinterpret_cast<const uint8_t *>(response.data());
    co_await writeAll(clientCtx->socket, {data, response.size()}, std::move(ct));
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

    [[nodiscard]] static CoroTask<Socks5Request> readRequest(const std::shared_ptr<ClientContextCoro> clientCtx,
                                                             const CancellationTokenSource &setupCts) {
        auto readBytes = [&clientCtx, &setupCts](auto &buffer, size_t &offset, const size_t n) -> CoroTask<void> {
            buffer.resize(offset + n);
            while (offset < buffer.size()) {
                const size_t read = co_await clientCtx->socket->read({buffer.data() + offset, buffer.size() - offset},
                                                                     setupCts.getToken());
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

    static Socks5Response ipv4(const uint32_t addr, const uint16_t port) {
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

    static Socks5Response ipv4Any(const uint16_t port) {
        return ipv4(0, port);
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

    void serializeTo(std::vector<uint8_t> &buffer) const {
        buffer.resize(size());
        serialize(buffer);
    }
};

[[nodiscard]] CoroTask<> handleSocks5Request(const std::shared_ptr<ClientContextCoro> clientCtx,
                                             const CancellationTokenSource &setupCts) {
    const auto req = co_await Socks5Request::readRequest(clientCtx, setupCts);
    clientCtx->targetEndpoint = req.targetEndpoint;
}

[[nodiscard]] CoroTask<> sendSocks5Success(const std::shared_ptr<ClientContextCoro> clientCtx, CancellationTokenOpt ct) {
    Socks5Response::ipv4Any(clientCtx->targetEndpoint.port()).serializeTo(clientCtx->buffer);
    co_await writeAll(clientCtx->socket, {clientCtx->buffer.data(), clientCtx->buffer.size()}, std::move(ct));
}

void sendSocks5FailureSync(const std::shared_ptr<ClientContextCoro> &clientCtx) {
    Socks5Response response;
    response.rep = Socks5::Rep::GeneralFailure;
    response.atyp = Socks5::Atyp::IpV4;
    response.bndAddr = {0, 0, 0, 0};
    response.bndPort = 0;

    std::vector<uint8_t> buffer;
    response.serializeTo(buffer);

    if (const int fd = clientCtx->socket->fd(); fd >= 0) {
        send(fd, buffer.data(), buffer.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
    }
}

struct DataForwardContext final {
    std::atomic<bool> clientReadDone = false;
    std::atomic<bool> backendReadDone = false;
    std::atomic<bool> closed = false;
    std::shared_ptr<ClientContextCoro> client;
    BackendSocketPtr backend;
    std::shared_ptr<CompletionSignal> completionSignal = std::make_shared<CompletionSignal>();
    IdleTimer idleTimer{std::chrono::seconds(Constants::IDLE_TIMEOUT_SEC)};
    EpollScheduler *scheduler = nullptr;
    std::shared_ptr<ProxyStats> proxyStats;
    CancellationTokenSource cts;
    std::uint64_t id = 0;

    DataForwardContext(std::shared_ptr<ClientContextCoro> client_,
                       BackendSocketPtr backend_,
                       std::shared_ptr<ProxyStats> proxyStats_,
                       CancellationTokenSource cts_) :
        client(std::move(client_)),
        backend(std::move(backend_)),
        proxyStats(std::move(proxyStats_)),
        cts(std::move(cts_)) {
        idleTimer.arm();
        proxyStats->totalConnections.fetch_add(1);
        id = proxyStats->activeConnections.fetch_add(1);
    }

    DataForwardContext(const DataForwardContext &) = delete;
    DataForwardContext &operator=(const DataForwardContext &) = delete;

    ~DataForwardContext() {
        proxyStats->activeConnections.fetch_sub(1);
    }

    void onDirectionDone(const bool isClientDirection) {
        auto &self = isClientDirection ? clientReadDone : backendReadDone;
        self.store(true);
        if (clientReadDone && backendReadDone) {
            completionSignal->signal();
        } else {
            cts.requestStop();
        }
    }

    void closeAll() {
        if (scheduler != nullptr) {
            if (backend != nullptr && backend->fd() >= 0) {
                scheduler->forceRemoveFd(backend->fd());
            }
            if (client != nullptr && client->socket != nullptr && client->socket->fd() >= 0) {
                scheduler->forceRemoveFd(client->socket->fd());
            }
        }

        if (closed.exchange(true, std::memory_order_acq_rel)) {
            return;
        }

        if (backend != nullptr) {
            backend->close();
        }
        if (client != nullptr) {
            client->closeSocket();
        }
    }

    [[nodiscard]] std::string toString() const {
        return std::format("{}:{}", id, client->targetEndpoint.host());
    }
};

template<typename ReadFunc, typename WriteFunc, typename SourceIsEofFunc, typename DestIsEofFunc>
[[nodiscard]] CoroTask<> forwardDirection(const std::shared_ptr<DataForwardContext> state,
                                          ReadFunc read,
                                          WriteFunc write,
                                          SourceIsEofFunc sourceIsEof,
                                          DestIsEofFunc destIsEof,
                                          std::atomic<bool> &sourceDoneFlag,
                                          std::atomic<bool> &destDoneFlag,
                                          const bool isClientDirection) {
    constexpr size_t kBufferSize = Constants::BUFFER_SIZE;
    Buffer buffer(kBufferSize);

    try {
        while (!sourceDoneFlag.load()) {
            if (destDoneFlag.load() || destIsEof()) {
                break;
            }
            if (sourceIsEof()) {
                break;
            }

            const size_t readBytes = co_await read(buffer.span());
            if (readBytes == 0) {
                break;
            }

            state->idleTimer.arm();

            size_t writtenBytes = 0;
            while (writtenBytes < readBytes) {
                if (destDoneFlag.load() || destIsEof()) {
                    break;
                }
                const size_t chunk = co_await write(buffer.subspan(writtenBytes, readBytes - writtenBytes));
                if (chunk == 0) {
                    break;
                }
                writtenBytes += chunk;
                state->idleTimer.arm();
            }
            if (isClientDirection) {
                state->proxyStats->totalOutBytes.fetch_add(writtenBytes, std::memory_order_relaxed);
            } else {
                state->proxyStats->totalInBytes.fetch_add(readBytes, std::memory_order_relaxed);
            }
        }
    } catch (const CancellationTokenException &e) {
        log_d("{}: {}->{} data forwarding canceled\n", state->toString(), isClientDirection ? "C" : "B", isClientDirection ? "B" : "C");
    } catch (const std::exception &e) {
        log_e("{}: {}->{} exception: {}\n", state->toString(), isClientDirection ? "C" : "B", isClientDirection ? "B" : "C", e.what());
    } catch (...) {
    }

    state->onDirectionDone(isClientDirection);
}

[[nodiscard]] CoroTask<> forwardClientToBackend(const std::shared_ptr<DataForwardContext> state) {
    return forwardDirection(
            state,
            [state](const std::span<uint8_t> buf) -> CoroTask<size_t> {
                co_return co_await state->client->socket->read(buf, state->cts.getToken());
            },
            [state](const std::span<const uint8_t> buf) -> CoroTask<size_t> {
                co_return co_await state->backend->writeAsync(buf, state->cts.getToken());
            },
            [state]() -> bool {
                return state->client->socket->isEof();
            },
            [state]() -> bool {
                return state->backend->isEof();
            },
            state->clientReadDone,
            state->backendReadDone,
            true);
}

[[nodiscard]] CoroTask<> forwardBackendToClient(const std::shared_ptr<DataForwardContext> state) {
    return forwardDirection(
            state,
            [state] (const std::span<uint8_t> buf) mutable -> CoroTask<size_t> {
                co_return co_await state->backend->readAsync(buf, state->cts.getToken());
            },
            [state](const std::span<const uint8_t> buf) -> CoroTask<size_t> {
                co_return co_await writeAll(state->client->socket, buf, state->cts.getToken());
            },
            [state]() -> bool {
                return state->backend->isEof();
            },
            [state]() -> bool {
                return state->client->socket->isEof();
            },
            state->backendReadDone,
            state->clientReadDone,
            false);
}

[[nodiscard]] CoroTask<> forwardData(const std::shared_ptr<ClientContextCoro> clientCtx,
                                     const BackendSocketPtr backendSocket,
                                     CancellationTokenSource cts,
                                     const std::shared_ptr<ProxyStats> &proxyStats) {
    const auto state = std::make_shared<DataForwardContext>(clientCtx, backendSocket, proxyStats, std::move(cts));

    auto *scheduler = co_await GetScheduler{};
    state->scheduler = scheduler;

    size_t prefetchedOffset = 0;
    while (prefetchedOffset < clientCtx->prefetchedClientData.size()) {
        const std::span<const uint8_t> remaining(clientCtx->prefetchedClientData.data() + prefetchedOffset,
                                                 clientCtx->prefetchedClientData.size() - prefetchedOffset);
        const size_t written = co_await state->backend->writeAsync(remaining, state->cts.getToken());
        if (written == 0 || written > remaining.size()) {
            throw std::runtime_error("Backend closed while forwarding prefetched CONNECT data");
        }
        prefetchedOffset = safeAdd(prefetchedOffset, written);
        state->proxyStats->totalOutBytes.fetch_add(written, std::memory_order_relaxed);
        state->idleTimer.arm();
    }
    clientCtx->prefetchedClientData.clear();

    auto clientToBackend = forwardClientToBackend(state);
    auto backendToClient = forwardBackendToClient(state);

    clientToBackend.startDetached(*scheduler);
    backendToClient.startDetached(*scheduler);

    while (!(state->clientReadDone.load() && state->backendReadDone.load())) {
        const auto readyFds = co_await MultiFdAwaiter{
            {
                {state->completionSignal->getFd(), EPOLLIN},
                {state->idleTimer.getFd(), EPOLLIN}
            }
        };

        for (const int fd: readyFds) {
            if (fd == state->completionSignal->getFd()) {
                state->completionSignal->drain();
                break;
            }
            if (fd == state->idleTimer.getFd()) {
                state->idleTimer.drain();
                state->cts.requestStop();
                break;
            }
        }
    }

    state->closeAll();
}

struct ClientSetupState final {
    CancellationTokenSource cts;
    std::atomic_bool finished = false;
};

struct ClientSetupGuard final {
    explicit ClientSetupGuard(std::shared_ptr<ClientSetupState> state_) : state(std::move(state_)) {}

    ~ClientSetupGuard() {
        state->finished.store(true);
    }

    std::shared_ptr<ClientSetupState> state;
};

[[nodiscard]] CoroTask<> enforceClientSetupTimeout(const std::shared_ptr<ClientSetupState> state) {
    try {
        co_await TimerAwaiter{Constants::CLIENT_SETUP_TIMEOUT, co_await GetCancellationToken{}};
    } catch (const CancellationTokenException &) {
        co_return;
    }
    if (!state->finished.load()) {
        state->cts.requestStop();
    }
}

[[nodiscard]] CoroTask<> handleClient(const BackendFactory backendFactory,
                                      const std::shared_ptr<ClientContextCoro> client,
                                      const std::shared_ptr<ProxyStats> &proxyStats) {
    const auto setupState = std::make_shared<ClientSetupState>();
    const ClientSetupGuard setupGuard(setupState);
    auto setupTimeout = enforceClientSetupTimeout(setupState);
    setupTimeout.startDetached(*co_await GetScheduler{});

    bool tunnelEstablished = false;
    bool failed = false;
    try {
        co_await detectClientProtocol(client, setupState->cts);
        if (client->protocol == ClientProtocol::Socks5) {
            co_await handleSocks5Handshake(client, setupState->cts);
            co_await handleSocks5Request(client, setupState->cts);
        } else {
            if (const auto request = co_await readHttpConnectRequest(client, setupState->cts); !request) {
                co_await sendHttpConnectResponse(client, request.error().status, setupState->cts.getToken());
                client->closeSocket();
                co_return;
            }
        }

        const auto backendSocket = backendFactory ? backendFactory(client->targetEndpoint) : nullptr;

        if (backendSocket == nullptr) {
            if (client->protocol == ClientProtocol::Socks5) {
                sendSocks5FailureSync(client);
            } else {
                co_await sendHttpConnectResponse(client, HttpConnect::Status::BadGateway, setupState->cts.getToken());
            }
            client->closeSocket();
            co_return;
        }

        if (const auto connectResult =
                co_await backendSocket->connectAsync(client->targetEndpoint, setupState->cts.getToken());
            connectResult != ResultCode::Ok) {
            if (client->protocol == ClientProtocol::Socks5) {
                sendSocks5FailureSync(client);
            } else {
                co_await sendHttpConnectResponse(client, HttpConnect::Status::BadGateway, setupState->cts.getToken());
            }
            client->closeSocket();
            co_return;
        }

        if (client->protocol == ClientProtocol::Socks5) {
            co_await sendSocks5Success(client, setupState->cts.getToken());
        } else {
            co_await sendHttpConnectResponse(client, HttpConnect::Status::ConnectionEstablished,
                                             setupState->cts.getToken());
        }
        setupState->finished.store(true);
        tunnelEstablished = true;
        co_await forwardData(client, backendSocket, CancellationTokenSource{}, proxyStats);
    } catch (...) {
        failed = true;
    }

    if (failed && !tunnelEstablished) {
        if (client->protocol == ClientProtocol::HttpConnect) {
            try {
                co_await sendHttpConnectResponse(client, HttpConnect::Status::BadRequest, co_await GetCancellationToken());
            } catch (...) {
            }
        } else {
            sendSocks5FailureSync(client);
        }
        client->closeSocket();
    }
}

CoroTask<> printProxyStats(const std::shared_ptr<const ProxyStats> stats,
                           const std::atomic_bool &isStopRequested) {
    while (!isStopRequested) {
        log_d("AC:{}, TC:{}, IN:{:.1f}, OUT:{:.1f}\n",
            stats->activeConnections.load(std::memory_order_relaxed),
            stats->totalConnections.load(std::memory_order_relaxed),
            static_cast<double>(stats->totalInBytes.load(std::memory_order_relaxed)) / 1024. / 1024.,
            static_cast<double>(stats->totalOutBytes.load(std::memory_order_relaxed)) / 1024. / 1024.);
        try {
            co_await TimerAwaiter{Constants::PRINT_STATS_INTERVAL, co_await GetCancellationToken{}};
        } catch (const CancellationTokenException &) {
            break;
        }
    }
}

[[nodiscard]] CoroTask<> startServer(const ProxyConfig config,
                                     const std::shared_ptr<ProxyStats> proxyStats,
                                     std::atomic_bool &isStopRequested) {
    Socket serverSocket;
    serverSocket.setReuseAddr(true);
    sockaddr_in listenAddress{};
    listenAddress.sin_family = AF_INET;
    listenAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listenAddress.sin_port = htons(config.listenPort);
    log_d("Listening endpoint: 127.0.0.1:{}\n", config.listenPort);
    if (!serverSocket.bind(Endpoint(listenAddress))) {
        throw std::runtime_error(
                std::format("Failed to bind server socket on port {}: {}", config.listenPort, std::strerror(errno)));
    }

    log_d("Server task started\n");
    auto *const scheduler = co_await GetScheduler{};
    auto proxyStatsPrinter = printProxyStats(proxyStats, isStopRequested);
    proxyStatsPrinter.startDetached(*scheduler);
    while (true) {
        try {
            auto [socket, endpoint] = co_await serverSocket.listen(scheduler->getCancellationTokenSource().getToken());
            log_d("Server: new connection port: {}\n", endpoint.port());
            auto handler = handleClient(config.backendFactory, std::make_shared<ClientContextCoro>(endpoint, socket), proxyStats);
            handler.startDetached(*scheduler);
        } catch (const CancellationTokenException &) {
            isStopRequested.store(true);
            log_d("Server task finished\n");
            break;
        } catch (const std::exception &) {
            throw;
        }
    }
}

struct ServerOutcome final {
    void setFailure(std::exception_ptr failure_) {
        std::lock_guard lock(mutex);
        if (failure == nullptr) {
            failure = std::move(failure_);
        }
    }

    [[nodiscard]] std::exception_ptr getFailure() const {
        std::lock_guard lock(mutex);
        return failure;
    }

private:
    mutable std::mutex mutex;
    std::exception_ptr failure;
};

[[nodiscard]] CoroTask<> superviseServer(const ProxyConfig config,
                                         const std::shared_ptr<ProxyStats> proxyStats,
                                         std::atomic_bool &isStopRequested,
                                         CancellationTokenSource &cts,
                                         const std::shared_ptr<ServerOutcome> outcome) {
    try {
        co_await startServer(config, proxyStats, isStopRequested);
    } catch (...) {
        outcome->setFailure(std::current_exception());
    }
    isStopRequested.store(true);
    cts.requestStop();
}

} // namespace

SSHProxy::SSHProxy(CancellationTokenSource &cts_) :
    cts(cts_) {
    if (const int result = libssh2_init(0); result != 0) {
        throw std::runtime_error(std::format("libssh2_init failed: {}", result));
    }
}

SSHProxy::~SSHProxy() {
    requestStop();
    waitForFinish();
    libssh2_exit();
}

void SSHProxy::start(const ProxyConfig &proxyConfig,
                     const std::optional<StartCallback> &startCb,
                     const std::optional<FinishCallback> &stopCb,
                     const std::optional<ErrorCallback> &errorCb) {
    if (mainThread != std::nullopt) {
        throw std::runtime_error("Already started");
    }
    this->config = proxyConfig;
    isStopRequested = false;
    mainThread = std::jthread([this, startCb, stopCb, errorCb] { mainLoop(startCb, stopCb, errorCb); });
}

void SSHProxy::requestStop() noexcept {
    cts.requestStop();
    isStopRequested = true;
}

void SSHProxy::waitForFinish() {
    if (mainThread != std::nullopt && mainThread.value().joinable()) {
        mainThread.value().join();
    }
}

void SSHProxy::mainLoop(const std::optional<StartCallback> &startCb,
                        const std::optional<FinishCallback> &stopCb,
                        const std::optional<ErrorCallback> &errorCb) {
    std::exception_ptr failure;
    try {
        EpollScheduler sched(cts);
        const auto outcome = std::make_shared<ServerOutcome>();
        auto supervisor = superviseServer(config.value(), proxyStats, isStopRequested, cts, outcome);
        supervisor.startDetached(sched);

        failure = outcome->getFailure();
        if (failure == nullptr) {
            try {
                log_d("SOCKS5 / HTTP CONNECT proxy started on port: {}\n", config.value().listenPort);
                log_d("Proxy started. Press Ctrl+C to stop...\n");
                if (startCb) {
                    startCb.value()();
                }
            } catch (...) {
                failure = std::current_exception();
                cts.requestStop();
            }
        }

        try {
            sched.run();
        } catch (...) {
            if (failure == nullptr) {
                failure = std::current_exception();
            }
            cts.requestStop();
        }
        if (failure == nullptr) {
            failure = outcome->getFailure();
        }
    } catch (...) {
        failure = std::current_exception();
    }

    if (failure != nullptr) {
        std::string message = "Unknown proxy failure";
        try {
            std::rethrow_exception(failure);
        } catch (const std::exception &e) {
            message = e.what();
        } catch (...) {
        }
        log_e("Proxy exception: {}\n", message);
        if (errorCb) {
            try {
                errorCb.value()(-1, message);
            } catch (const std::exception &e) {
                log_e("Error callback exception: {}\n", e.what());
            } catch (...) {
                log_e("Unknown error callback exception\n");
            }
        }
    }

    log_d("Proxy finished\n");
    if (stopCb) {
        try {
            stopCb.value()();
        } catch (const std::exception &e) {
            log_e("Finish callback exception: {}\n", e.what());
        } catch (...) {
            log_e("Unknown finish callback exception\n");
        }
    }
}
