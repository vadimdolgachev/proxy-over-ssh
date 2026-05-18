//
// Created by vadim on 31.10.2025.
//

#include <format>
#include <limits>
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
#include "Logger.h"
#include "SSHProxy.h"
#include "Socket.h"
#include "Types.h"

namespace {
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
    };

    constexpr size_t safeAdd(const size_t a, const size_t b) {
        if (a > std::numeric_limits<size_t>::max() - b) {
            throw std::runtime_error("Integer overflow in size calculation");
        }
        return a + b;
    }

    [[nodiscard]] CoroTask<> readUntil(const std::shared_ptr<ClientContextCoro> clientCtx, const size_t totalSize) {
        if (clientCtx->buffer.size() < totalSize) {
            throw std::runtime_error("Buffer too small for requested read size");
        }

        size_t totalRead = 0;
        while (totalRead < totalSize) {
            const size_t remaining = clientCtx->buffer.size() - totalRead;
            const size_t read = co_await clientCtx->socket->read(
                {clientCtx->buffer.data() + totalRead, remaining},
                co_await GetCancellationToken()
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
            for (const auto &[fd, events]: fds) {
                this->getScheduler()->add(events, fd, h);
            }
        }

        std::vector<int> await_resume() {
            for (const auto &[fd, _]: fds) {
                this->getScheduler()->remove(fd, handle);
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


    [[nodiscard]] static CoroTask<Socks5Negotiation> parse(const std::shared_ptr<ClientContextCoro> clientCtx) {
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

[[nodiscard]] CoroTask<> handleSocks5Handshake(const std::shared_ptr<ClientContextCoro> clientCtx) {
    const auto negotiation = co_await Socks5Negotiation::parse(clientCtx);

    const bool hasNoAuth = std::ranges::find_if(negotiation.nmethodsData, [](const auto c) {
                               return c == Socks5::Auth::NoAuth;
                           }) != negotiation.nmethodsData.end();

    const uint8_t selectedMethod = hasNoAuth ? Socks5::Auth::NoAuth : 0xFF;

    clientCtx->buffer.resize(2);
    clientCtx->buffer[0] = Socks5::Version;
    clientCtx->buffer[1] = selectedMethod;
    const size_t length = co_await clientCtx->socket->write(
        {clientCtx->buffer.data(),
            clientCtx->buffer.size()},
            co_await GetCancellationToken());
    if (length != clientCtx->buffer.size()) {
        throw std::runtime_error("Failed to write to client");
    }

    if (selectedMethod == 0xFF) {
        throw std::runtime_error("No acceptable SOCKS5 authentication method");
    }
}

[[nodiscard]] CoroTask<size_t> writeAll(const SocketPtr &socket, std::span<const uint8_t> data, CancellationTokenOpt ct) {
    size_t offset = 0;
    while (offset < data.size()) {
        const size_t written =
                co_await socket->write({const_cast<uint8_t *>(data.data()) + offset, data.size() - offset}, std::move(ct));
        if (written == 0) {
            throw std::runtime_error("Socket closed during write");
        }
        offset += written;
    }
    co_return offset;
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

    [[nodiscard]] static CoroTask<Socks5Request> readRequest(const std::shared_ptr<ClientContextCoro> clientCtx) {
        auto readBytes = [&clientCtx](auto &buffer, size_t &offset, const size_t n) -> CoroTask<void> {
            buffer.resize(offset + n);
            while (offset < buffer.size()) {
                const size_t read = co_await clientCtx->socket->read({buffer.data() + offset, buffer.size() - offset}, co_await GetCancellationToken());
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

[[nodiscard]] CoroTask<> handleSocks5Request(const std::shared_ptr<ClientContextCoro> clientCtx) {
    const auto req = co_await Socks5Request::readRequest(clientCtx);
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
    std::optional<CancellationTokenSource> cts;
    std::shared_ptr<ProxyStats> proxyStats;

    DataForwardContext(std::shared_ptr<ClientContextCoro> client_,
                       BackendSocketPtr backend_,
                       std::shared_ptr<ProxyStats> proxyStats_) :
        client(std::move(client_)),
        backend(std::move(backend_)),
        proxyStats(std::move(proxyStats_)) {
        idleTimer.arm();
        proxyStats->totalConnections.fetch_add(1);
        proxyStats->activeConnections.fetch_add(1);
    }

    DataForwardContext(const DataForwardContext &) = delete;
    DataForwardContext &operator=(const DataForwardContext &) = delete;

    ~DataForwardContext() {
        proxyStats->activeConnections.fetch_sub(1);
    }

    void onDirectionDone(const bool isClientDirection) {
        auto &self = isClientDirection ? clientReadDone : backendReadDone;
        self.store(true);
        cts->requestStop();
        if (clientReadDone && backendReadDone) {
            completionSignal->signal();
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
        // log_d("{}->{} data forwarding canceled\n", isClientDirection ? "C" : "B", isClientDirection ? "B" : "C");
    } catch (const std::exception &e) {
        log_e("{}->{} exception: {}\n", isClientDirection ? "C" : "B", isClientDirection ? "B" : "C", e.what());
    } catch (...) {
    }

    state->onDirectionDone(isClientDirection);
}

[[nodiscard]] CoroTask<> forwardClientToBackend(const std::shared_ptr<DataForwardContext> state) {
    co_await forwardDirection(
            state,
            [state](const std::span<uint8_t> buf) -> CoroTask<size_t> {
                co_return co_await state->client->socket->read(buf, state->cts->getToken());
            },
            [state](const std::span<const uint8_t> buf) -> CoroTask<size_t> {
                co_return co_await state->backend->writeAsync(buf, state->cts->getToken());
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
    co_await forwardDirection(
            state,
            [state] (const std::span<uint8_t> buf) mutable -> CoroTask<size_t> {
                co_return co_await state->backend->readAsync(buf, state->cts->getToken());
            },
            [state](const std::span<const uint8_t> buf) -> CoroTask<size_t> {
                co_return co_await writeAll(state->client->socket, buf, state->cts->getToken());
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
    const auto state = std::make_shared<DataForwardContext>(clientCtx, backendSocket, proxyStats);

    auto *scheduler = co_await GetScheduler{};
    state->scheduler = scheduler;
    state->cts = cts;

    auto clientToBackend = forwardClientToBackend(state);
    auto backendToClient = forwardBackendToClient(state);

    clientToBackend.start(*scheduler);
    backendToClient.start(*scheduler);

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
                if (state->cts) {
                    state->cts->requestStop();
                }
                break;
            }
        }
    }
    state->closeAll();
}

[[nodiscard]] CoroTask<> handleClient(const BackendFactory backendFactory,
                                      Endpoint endpoint,
                                      SocketPtr socket,
                                      const std::shared_ptr<ProxyStats> &proxyStats) {
    const auto client = std::make_shared<ClientContextCoro>(endpoint, socket);
    try {
        co_await handleSocks5Handshake(client);
        co_await handleSocks5Request(client);

        const auto backendSocket = backendFactory(client->targetEndpoint);
        CancellationTokenSource cts;

        if (const auto connectResult = co_await backendSocket->connectAsync(client->targetEndpoint, cts.getToken());
            connectResult != ResultCode::Ok) {
            sendSocks5FailureSync(client);
            client->closeSocket();
            co_return;
        }

        co_await sendSocks5Success(client, cts.getToken());
        co_await forwardData(client, backendSocket, std::move(cts), proxyStats);
    } catch (const std::exception &) {
        sendSocks5FailureSync(client);
    } catch (...) {
        sendSocks5FailureSync(client);
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
    log_d("Listening port: {}\n", config.listenPort);
    if (!serverSocket.bind(Endpoint(config.listenPort))) {
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
            auto handler = handleClient(config.backendFactory, endpoint, socket, proxyStats);
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

} // namespace

SSHProxy::SSHProxy(CancellationTokenSource &cts_) :
    cts(cts_) {
    libssh2_init(0);
}

SSHProxy::~SSHProxy() {
    log_v("~SSHProxy\n");
    requestStop();
    libssh2_exit();
}

void SSHProxy::start(const ProxyConfig &proxyConfig,
                     const std::optional<StartCallback> &startCb,
                     const std::optional<FinishCallback> &stopCb) {
    if (mainThread != std::nullopt) {
        throw std::runtime_error("Already started");
    }
    this->config = proxyConfig;
    isStopRequested = false;
    mainThread = std::jthread([this, startCb, stopCb] { mainLoop(startCb, stopCb); });
}

void SSHProxy::requestStop() noexcept {
    log_d("SSHProxy::requestStop\n");
    cts.requestStop();
    isStopRequested = true;
}

void SSHProxy::waitForFinish() {
    if (mainThread != std::nullopt) {
        mainThread.value().join();
    }
}

void SSHProxy::mainLoop(const std::optional<StartCallback> &startCb, const std::optional<FinishCallback> &stopCb) {
    try {
        EpollScheduler sched(cts);
        auto task = startServer(config.value(), proxyStats, isStopRequested);
        task.start(sched);
        log_d("SOCKS5 proxy started on port: {}\n", config.value().listenPort);
        log_d("Proxy started. Press Ctrl+C to stop...\n");
        if (startCb) {
            startCb.value()();
        }
        sched.run();
        log_d("Proxy finished\n");
        if (stopCb) {
            stopCb.value()();
        }
    } catch (std::exception &e) {
        log_d("Exception: {}\n", e.what());
    }
}
