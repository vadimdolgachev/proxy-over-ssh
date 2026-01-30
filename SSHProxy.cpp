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
#include <cstdint>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <libssh2.h>

#include "CoroTask.h"
#include "Socket.h"

namespace {
    bool checkConnection(const int fd) {
        int err;
        socklen_t len = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err) {
            return false;
        }

        char tmp;
        const auto result = recv(fd, &tmp, 1, MSG_PEEK | MSG_DONTWAIT);
        if (result == 0) {
            return false;
        }
        if (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            return false;
        }
        return true;
    }
}

constexpr int BUFFER_SIZE = 2 * 8192;
constexpr int MAX_SIZE_SESSION_POOL = 25;
constexpr bool PRINT_VERBOSE_LOG = false;

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
}

class EPollManager final {
public:
    constexpr static std::uint32_t EPOLL_ET = EPOLLET;
    constexpr static std::uint32_t EPOLL_IN = EPOLLIN;
    constexpr static std::uint32_t EPOLL_OUT = EPOLLOUT;
    constexpr static std::uint32_t EPOLL_IO = EPOLL_IN | EPOLL_OUT;
    constexpr static std::uint32_t EPOLL_ERR = EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    constexpr static std::uint32_t EPOLL_IO_ERR = EPOLL_IO | EPOLL_ERR;

    explicit EPollManager(const size_t maxEvents = 128) : epollEvents(maxEvents),
                                                          epollFd(epoll_create1(0)) {
        if (epollFd == -1) {
            throw std::runtime_error("Failed to create epoll instance");
        }
    }

    EPollManager(const EPollManager &) = delete;

    EPollManager &operator=(const EPollManager &) = delete;

    ~EPollManager() {
        close(epollFd);
    }

    void add(const int fd, const uint32_t events) {
        epoll_event ev{};
        ev.events = events;
        ev.data.fd = fd;

        // TODO: check result
        if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev) == -1) {
            std::cerr << "Failed to add edfd to epoll: " << strerror(errno) << std::endl;
        }
    }

    void remove(const int fd) {
        // TODO: check result
        epoll_ctl(epollFd, EPOLL_CTL_DEL, fd, nullptr);
    }

    void modify(const int fd, const uint32_t events) {
        epoll_event ev{};
        ev.events = events;
        ev.data.fd = fd;

        // TODO: check result
        epoll_ctl(epollFd, EPOLL_CTL_MOD, fd, &ev);
    }

    [[nodiscard]] int wait(const int timeoutMs) noexcept {
        return epoll_wait(epollFd, epollEvents.data(),
                          static_cast<int>(epollEvents.size()), timeoutMs);
    }

    [[nodiscard]] epoll_event getEvent(const size_t index) const noexcept {
        return epollEvents[index];
    }

private:
    std::vector<epoll_event> epollEvents;
    const int epollFd;
};

struct Address final {
    std::string host;
    std::uint16_t port{};

    [[nodiscard]] std::string toString() const {
        return host + ":" + std::to_string(port);
    }
};

class SSHChannel final {
public:
    enum class State {
        CREATED,
        SEND_EOF,
        CLOSE,
        CLOSED
    };

    explicit SSHChannel(LIBSSH2_CHANNEL *const channel_) : channel(channel_) {
    }

    SSHChannel(const SSHChannel &) = delete;

    SSHChannel &operator=(const SSHChannel &) = delete;

    ~SSHChannel() {
        if (channel) {
            libssh2_channel_free(channel);
        }
    }

    [[nodiscard]] ResultCode closeConnection() {
        if (state == State::CREATED) {
            if (libssh2_channel_send_eof(channel) == LIBSSH2_ERROR_EAGAIN) {
                return ResultCode::ErrAgain;
            }
            state = State::CLOSE;
        }
        if (state == State::CLOSE) {
            if (libssh2_channel_close(channel) == LIBSSH2_ERROR_EAGAIN) {
                return ResultCode::ErrAgain;
            }
            state = State::CLOSED;
        }
        if (state == State::CLOSED) {
            if (libssh2_channel_wait_closed(channel) == LIBSSH2_ERROR_EAGAIN) {
                return ResultCode::ErrAgain;
            }
            return ResultCode::Ok;
        }
        return ResultCode::ErrIO;
    }

    [[nodiscard]] ssize_t write(const std::span<const uint8_t> buffer) noexcept {
        return libssh2_channel_write(channel, reinterpret_cast<const char *>(buffer.data()), buffer.size());
    }

    [[nodiscard]] ssize_t read(std::span<uint8_t> buffer) noexcept {
        return libssh2_channel_read(channel, reinterpret_cast<char *>(buffer.data()), buffer.size());
    }

private:
    LIBSSH2_CHANNEL *channel = nullptr;
    State state = State::CREATED;
};

class SSH2Session final {
public:
    class InitSessionError final : public std::exception {
    };

    const int fd;
    const std::shared_ptr<EPollManager> epollManager;

    explicit SSH2Session(const int fd_,
                         std::shared_ptr<EPollManager> epollManager_) : fd(fd_),
                                                                        epollManager(std::move(epollManager_)),
                                                                        session(libssh2_session_init()) {
        if (session == nullptr) {
            throw InitSessionError();
        }
        libssh2_session_set_blocking(session, 0);
    }

    SSH2Session(const SSH2Session &) = delete;

    SSH2Session &operator=(const SSH2Session &) = delete;

    ~SSH2Session() {
        libssh2_session_disconnect(session, nullptr);
        libssh2_session_free(session);
        close(fd);
        epollManager->remove(fd);
    }

    enum class State {
        HANDSHAKE,
        AUTHENTICATE,
        CONNECTED
    };

    [[nodiscard]] ResultCode handshake(const int socket) {
        state = State::HANDSHAKE;
        if (const int rc = libssh2_session_handshake(session, socket); rc == LIBSSH2_ERROR_EAGAIN) {
            return ResultCode::ErrAgain;
        }
        state = State::AUTHENTICATE;
        log_v("{}, Handshake done\n", socket);
        return ResultCode::Ok;
    }

    [[nodiscard]] ResultCode authenticate(const SSHConfig &config) {
        state = State::AUTHENTICATE;
        int rc;
        if (config.privateKeyData.has_value()) {
            rc = libssh2_userauth_publickey_frommemory(session,
                                                       config.username.c_str(),
                                                       config.username.length(),
                                                       nullptr,
                                                       0,
                                                       config.privateKeyData.value().c_str(),
                                                       config.privateKeyData.value().length(),
                                                       nullptr);
        } else if (config.privateKeyPath.has_value()) {
            rc = libssh2_userauth_publickey_fromfile_ex(session,
                                                        config.username.c_str(),
                                                        static_cast<unsigned int>(config.username.length()),
                                                        nullptr,
                                                        config.privateKeyPath.value().c_str(),
                                                        nullptr);
        } else {
            return ResultCode::ErrInvalidPrivateKey;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            return ResultCode::ErrAgain;
        }
        state = State::CONNECTED;
        log_v("Authentication done to: {}:{}\n", config.host, config.port);
        return ResultCode::Ok;
    }

    [[nodiscard]] std::expected<std::shared_ptr<SSHChannel>, ResultCode> createChannel(const Address &addr) {
        if (state != State::CONNECTED) {
            log_e("SSH2 session not created: %{}:%{}\n", addr.host, addr.port);
            return std::unexpected(ResultCode::ErrUnknown);
        }

        auto *const channel = libssh2_channel_direct_tcpip_ex(session, addr.host.c_str(), addr.port, "::1", 0);
        if (channel == nullptr) {
            if (const int error = libssh2_session_last_errno(session); error == LIBSSH2_ERROR_EAGAIN) {
                return std::unexpected(ResultCode::ErrAgain);
            } else {
                hasChannelError = true;
                log_e("{}, Failed to create ssh channel to: {}, error: {}\n", -1,
                      addr.toString(), error);
                return std::unexpected(ResultCode::ErrIO);
            };
        }
        hasChannelError = false;
        return std::make_shared<SSHChannel>(channel);
    }

    [[nodiscard]] State getState() const {
        return state;
    }

    [[nodiscard]] bool hasChannelCreatingError() const {
        return hasChannelError;
    }

private:
    LIBSSH2_SESSION *session = nullptr;
    State state = State::HANDSHAKE;
    bool hasChannelError = false;
};

std::unique_ptr<SSH2Session>
createSshSession(const int fd, const std::shared_ptr<EPollManager> &epollManager) {
    return std::make_unique<SSH2Session>(fd, epollManager);
}

void destroySshSession([[maybe_unused]] std::deque<std::unique_ptr<SSH2Session> > &sessionObjectPool,
                       [[maybe_unused]] std::unique_ptr<SSH2Session> sshSession) {
}

struct SSH2Context final {
    std::unique_ptr<SSH2Session> session;
    std::deque<std::unique_ptr<SSH2Session> > &sessionObjectPool;
    std::shared_ptr<SSHChannel> channel;
    bool isAuthenticated = false;

    ~SSH2Context() {
        channel.reset();
        if (sessionObjectPool.size() < MAX_SIZE_SESSION_POOL) {
            if (!session->hasChannelCreatingError()) {
                sessionObjectPool.push_back(std::move(session));
            } else {
                log_e("Do not cache ssh session\n");
            }
        } else {
            log_d("Ssh session object pool limit exceeded\n");
        }
    }
};

struct ClientContext final {
    enum class State {
        NONE,
        HANDSHAKE,
        REQUEST,
        SSH_SERVER_CONNECTING,
        SSH_SERVER_AUTHENTICATE,
        SSH_CHANNEL_CREATING,
        FORWARDING,
        CHANNEL_CLOSING
    };

    explicit ClientContext(const int fd_) : fd(fd_) {
    }

    ClientContext(const ClientContext &) = delete;

    ClientContext &operator=(const ClientContext &) = delete;

    ~ClientContext();

    const int fd;
    std::unique_ptr<SSH2Context> sshContext;
    std::vector<uint8_t> readBuffer;
    std::vector<uint8_t> writeBuffer;
    State state = State::NONE;
    Address addr;
    size_t totalBytesRead = 0;
    size_t totalBytesWritten = 0;
    std::chrono::high_resolution_clock::time_point requestTime;
};

ClientContext::~ClientContext() {
    close(fd);
}

ResultCode SSHProxy::sshRead(const std::shared_ptr<ClientContext> &clientCtx) {
    uint8_t buffer[BUFFER_SIZE];
    ssize_t bytesRead = 0;
    do {
        bytesRead = clientCtx->sshContext->channel->read({buffer, BUFFER_SIZE});
        log_v("{}, Ssh read bytes: {}, addr: {}\n",
              clientCtx->fd, bytesRead, clientCtx->addr.toString());
        if (bytesRead > 0) {
            clientCtx->writeBuffer.insert(clientCtx->writeBuffer.end(), buffer, buffer + bytesRead);
            clientCtx->totalBytesRead += static_cast<size_t>(bytesRead);
            if (const auto result = sendToClient(clientCtx); result == ResultCode::ErrIO) {
                return result;
            }
        } else if (bytesRead == LIBSSH2_ERROR_EAGAIN) {
            const auto currTime = std::chrono::high_resolution_clock::now();
            if (const auto spent = std::chrono::duration_cast<std::chrono::seconds>(currTime - clientCtx->requestTime);
                spent.count() > 15 && clientCtx->totalBytesRead == 0) {
                log_e("{}, Timeout, addr: {}\n", clientCtx->fd, clientCtx->addr.toString());
                return ResultCode::ErrTimeout;
            }
            return ResultCode::ErrAgain;
        } else if (bytesRead == LIBSSH2_ERROR_NONE) {
            return ResultCode::Ok;
        } else {
            log_e("{}, Channel read error, addr: {}\n", clientCtx->fd, clientCtx->addr.toString());
            return ResultCode::ErrIO;
        }
    } while (true);
    return ResultCode::Ok;
}

ResultCode SSHProxy::sshWrite(const std::shared_ptr<ClientContext> &clientCtx) {
    // Forward data to SSH channel
    size_t totalWritten = 0;
    if (clientCtx->readBuffer.empty()) {
        return ResultCode::Ok;
    }
    auto resultCode = ResultCode::Ok;
    while (totalWritten < clientCtx->readBuffer.size()) {
        const ssize_t bytesWritten = clientCtx->sshContext->channel->write(
            std::span(clientCtx->readBuffer.data() + totalWritten,
                      clientCtx->readBuffer.size() - totalWritten));

        log_v("{}, Ssh write bytes: {}, addr: {}\n", clientCtx->fd, bytesWritten, clientCtx->addr.toString());

        if (bytesWritten > 0) {
            clientCtx->totalBytesWritten += static_cast<size_t>(bytesWritten);
            totalWritten += static_cast<size_t>(bytesWritten);
        } else if (bytesWritten == LIBSSH2_ERROR_EAGAIN) {
            resultCode = ResultCode::ErrAgain;
        } else {
            log_e("{}, Ssh channel write error for client\n", clientCtx->fd);
            return ResultCode::ErrIO;
        }
    }

    if (totalWritten > 0) {
        clientCtx->readBuffer.erase(clientCtx->readBuffer.begin(),
                                    clientCtx->readBuffer.begin() + static_cast<ssize_t>(totalWritten));
        log_v("{}, Ssh write total bytes: {}, left: {}\n", clientCtx->fd, totalWritten,
              clientCtx->readBuffer.size());
    }
    return resultCode;
}

ResultCode SSHProxy::sendToClient(const std::shared_ptr<ClientContext> &clientCtx) {
    if (clientCtx->writeBuffer.empty()) {
        epollManager->modify(clientCtx->fd,
                             EPollManager::EPOLL_IN | EPollManager::EPOLL_ET | EPollManager::EPOLL_ERR);
        return ResultCode::Ok;
    }

    if (const ssize_t sent = send(clientCtx->fd, clientCtx->writeBuffer.data(), clientCtx->writeBuffer.size(),
                                  MSG_NOSIGNAL | MSG_DONTWAIT); sent > 0) {
        clientCtx->writeBuffer.erase(clientCtx->writeBuffer.begin(), clientCtx->writeBuffer.begin() + sent);

        if (!clientCtx->writeBuffer.empty()) {
            epollManager->modify(clientCtx->fd, EPollManager::EPOLL_ET | EPollManager::EPOLL_IO_ERR);
        } else {
            epollManager->modify(clientCtx->fd,
                                 EPollManager::EPOLL_IN | EPollManager::EPOLL_ET | EPollManager::EPOLL_ERR);
        }
    } else if (sent == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            epollManager->modify(clientCtx->fd, EPollManager::EPOLL_ET | EPollManager::EPOLL_IO_ERR);
            return ResultCode::ErrAgain;
        }
        log_d("{}, Send error for client: {}\n", clientCtx->fd, strerror(errno));
        return ResultCode::ErrIO;
    }
    return ResultCode::Ok;
}

SSHProxy::SSHProxy(const std::atomic_bool &stopSignalFlag_) : serverFd(-1),
                                                              stopSignalFlag(stopSignalFlag_) {
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

ResultCode SSHProxy::setupEpoll() {
    try {
        epollManager = std::make_shared<EPollManager>();
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        log_e("Failed to create epoll: {}", e.what());
        return ResultCode::ErrUnknown;
    }
    return ResultCode::Ok;
}

bool SSHProxy::setupLocalServer() {
    serverFd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (serverFd == -1) {
        log_e("Failed to create server socket: {}\n", strerror(errno));
        return false;
    }

    constexpr int opt = 1;
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    const Endpoint endpoint(config.value().listenPort);
    if (bind(serverFd, reinterpret_cast<const sockaddr *>(&endpoint.sockaddr()),
             sizeof(endpoint.sockaddr())) == -1) {
        log_e("Failed to bind server socket: {}\n", strerror(errno));

        close(serverFd);
        return false;
    }

    if (listen(serverFd, SOMAXCONN) == -1) {
        log_e("Failed to listen on server socket: {}\n", strerror(errno));
        close(serverFd);
        return false;
    }
    return true;
}

ResultCode SSHProxy::connectToSshServer(const std::shared_ptr<ClientContext> &clientCtx) {
    sockaddr_in sshAddr{};
    sshAddr.sin_family = AF_INET;
    sshAddr.sin_port = htons(config.value().ssh.port);
    inet_pton(AF_INET, config.value().ssh.host.c_str(), &sshAddr.sin_addr);

    if (const int result = connect(clientCtx->sshContext->session->fd, reinterpret_cast<sockaddr *>(&sshAddr),
                                   sizeof(sshAddr));
        result == -1 && errno != EINPROGRESS) {
        log_e("Failed to connect to SSH server: {}\n", strerror(errno));
        closeConnection(clientCtx);
        return ResultCode::ErrIO;
    }
    if (errno == EINPROGRESS) {
        return ResultCode::Ok;
    }
    return ResultCode::ErrAgain;
}

void SSHProxy::setupSshConnection(const std::shared_ptr<ClientContext> &clientCtx) {
    if (clientCtx->state == ClientContext::State::SSH_SERVER_CONNECTING) {
        std::unique_ptr<SSH2Session> session;
        if (!sshSessionObjectPool.empty()) {
            log_v("Ssh session object pool size: {}\n", sshSessionObjectPool.size());
            while (!sshSessionObjectPool.empty()) {
                auto cachedSession = std::move(sshSessionObjectPool.front());
                sshSessionObjectPool.pop_front();
                if (!checkConnection(cachedSession->fd)) {
                    continue;
                }
                session = std::move(cachedSession);
                break;
            }
        }
        if (!session) {
            const auto fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if (fd == -1) {
                log_e("Failed to create SSH socket: {}\n", strerror(errno));
                closeConnection(clientCtx);
                return;
            }
            session = createSshSession(fd, epollManager);
        }

        try {
            clientCtx->sshContext = std::make_unique<SSH2Context>(std::move(session), sshSessionObjectPool);
        } catch (std::exception &e) {
            log_e("Failed to create SSH session: {}\n", e.what());
            closeConnection(clientCtx);
            return;
        }

        sshToClientSockets[clientCtx->sshContext->session->fd] = clientCtx->fd;
        // Add SSH socket to epoll for connection completion
        epollManager->add(clientCtx->sshContext->session->fd,
                          EPollManager::EPOLL_ET | EPollManager::EPOLL_IO | EPollManager::EPOLL_ERR);

        if (clientCtx->sshContext->session->getState() != SSH2Session::State::CONNECTED) {
            if (const auto result = connectToSshServer(clientCtx); result != ResultCode::Ok) {
                //TODO: handle this error
                return;
            }
        }
        clientCtx->state = ClientContext::State::SSH_SERVER_AUTHENTICATE;
    }

    if (clientCtx->state == ClientContext::State::SSH_SERVER_AUTHENTICATE) {
        if (handleSessionAuthenticateClient(clientCtx) == ResultCode::Ok) {
            clientCtx->state = ClientContext::State::SSH_CHANNEL_CREATING;
            epollManager->modify(clientCtx->sshContext->session->fd, EPollManager::EPOLL_IN | EPollManager::EPOLL_ERR);
        }
    }

    if (clientCtx->state == ClientContext::State::SSH_CHANNEL_CREATING) {
        if (createSshChannel(clientCtx) == ResultCode::ErrIO) {
            closeConnection(clientCtx);
        }
    }
}

// Simplified client context for coroutine-based SOCKS5 proxy test
// Tracks connection state, socket, and buffer for async I/O operations
struct ClientContext2 final {
    enum class State {
        HANDSHAKE,
        REQUEST,
        SSH_SOCKET_CONNECT,
        FORWARDING,
        CLOSED
    };

    static constexpr size_t kInitialBufferSize = 1024;

    ClientContext2(const Endpoint endpoint_, SocketPtr socket_, std::vector<uint8_t> buffer_)
        : endpoint(endpoint_),
          socket(std::move(socket_)),
          buffer(std::move(buffer_)) {
    }

    // Delete copy operations (socket is shared_ptr, but prevent accidental copies)
    ClientContext2(const ClientContext2 &) = delete;

    ClientContext2 &operator=(const ClientContext2 &) = delete;

    // Allow move operations
    ClientContext2(ClientContext2 &&) = default;

    ClientContext2 &operator=(ClientContext2 &&) = default;

    ~ClientContext2() {
        if (socket && socket->fd() != -1) {
            std::cout << "ClientContext2 destroyed for endpoint: "
                    << endpoint.ip() << ":" << endpoint.port() << '\n';
        }
    }

    // Socket operations
    [[nodiscard]] bool isConnected() const noexcept {
        return socket && socket->fd() != -1;
    }

    void closeSocket() noexcept {
        if (socket) {
            socket->close();
        }
    }

    // State management
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
    SocketPtr socket;
    std::vector<uint8_t> buffer;
    Endpoint targetEndpoint;

private:
    State state = State::HANDSHAKE;
};

CoroTask<void> handleSocks5Handshake(const std::shared_ptr<ClientContext2> clientCtx) {
    size_t length = co_await clientCtx->socket->read({clientCtx->buffer.data(), clientCtx->buffer.size()});
    std::cout << "length: " << length << '\n';

    // Minimum handshake: VER(1) + NMETHODS(1)
    if (length < 2) {
        throw std::runtime_error("SOCKS5 handshake too short");
    }

    const uint8_t version = clientCtx->buffer[0];
    const uint8_t nmethodLength = clientCtx->buffer[1];
    std::cout << "version: " << static_cast<int>(version) << ", nmethodLength: " << static_cast<int>(nmethodLength) <<
            '\n';

    if (version != Socks5::Version) {
        throw std::runtime_error("SOCKS5 version mismatch");
    }
    constexpr size_t nmethodsPos = 2;
    // Validate we received all methods bytes
    if (length < nmethodsPos + nmethodLength) {
        throw std::runtime_error("SOCKS5 handshake incomplete");
    }

    std::span<const uint8_t> nmethodsData = {&clientCtx->buffer[nmethodsPos], nmethodLength};
    // Scan methods for NoAuth (0x00)
    const bool hasNoAuth = std::ranges::find_if(nmethodsData, [](const auto c) {
        return c == Socks5::Auth::NoAuth;
    }) != nmethodsData.end();

    // Determine selected method (0x00=NoAuth, 0xFF=no acceptable method)
    const uint8_t selectedMethod = hasNoAuth ? Socks5::Auth::NoAuth : 0xFF;

    // Always send response first (RFC 1928 requirement)
    clientCtx->buffer[0] = Socks5::Version;
    clientCtx->buffer[1] = selectedMethod;
    clientCtx->buffer.resize(2);
    length = co_await clientCtx->socket->write({clientCtx->buffer.data(), clientCtx->buffer.size()});
    if (length != clientCtx->buffer.size()) {
        throw std::runtime_error("Failed to write to client");
    }

    // Only after sending response, close connection if no acceptable method
    if (selectedMethod == 0xFF) {
        throw std::runtime_error("No acceptable SOCKS5 authentication method");
    }

    // Handshake successful, transition to REQUEST state
    clientCtx->setState(ClientContext2::State::REQUEST);
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

    static Socks5Request deserialize(const uint8_t *buffer) {
        return Socks5Request{
            .version = buffer[0],
            .cmd = buffer[1],
            .rsv = buffer[2],
            .atyp = buffer[3]
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

    // Create IPv4 response
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

    // Create IPv6 response
    static Socks5Response ipv6(const uint8_t addr[16], uint16_t port) {
        Socks5Response resp;
        resp.atyp = Socks5::Atyp::IpV6;
        resp.bndAddr.assign(addr, addr + 16);
        resp.bndPort = port;
        return resp;
    }

    // Create domain response
    static Socks5Response domain(const std::string &domain, uint16_t port) {
        Socks5Response resp;
        resp.atyp = Socks5::Atyp::Domain;
        resp.bndAddr.resize(1 + domain.size());
        resp.bndAddr[0] = static_cast<uint8_t>(domain.size());
        std::memcpy(resp.bndAddr.data() + 1, domain.data(), domain.size());
        resp.bndPort = port;
        return resp;
    }

    // Create dummy IPv4 response (0.0.0.0)
    static Socks5Response dummy(uint16_t port) {
        return ipv4(0, port);
    }

    // Create response from host string (attempts IPv6, then IPv4, else domain)
    static Socks5Response fromHost(const std::string &host, uint16_t port) {
        sockaddr_in6 sa6{};
        sockaddr_in sa{};

        if (inet_pton(AF_INET6, host.c_str(), &sa6.sin6_addr) == 1) {
            // IPv6 address
            uint8_t addr[16];
            std::memcpy(addr, &sa6.sin6_addr, 16);
            return ipv6(addr, port);
        }
        if (inet_pton(AF_INET, host.c_str(), &sa.sin_addr) == 1) {
            // IPv4 address
            const uint32_t addr = ntohl(sa.sin_addr.s_addr);
            return ipv4(addr, port);
        }
        // Domain name
        return domain(host, port);
    }

    // Calculate total serialized size
    [[nodiscard]] size_t size() const {
        return kHeaderSize + bndAddr.size() + 2; // +2 for port
    }

    // Serialize to buffer
    void serialize(uint8_t *buffer) const {
        buffer[0] = version;
        buffer[1] = rep;
        buffer[2] = rsv;
        buffer[3] = atyp;
        std::memcpy(buffer + kHeaderSize, bndAddr.data(), bndAddr.size());
        const size_t portOffset = kHeaderSize + bndAddr.size();
        buffer[portOffset] = static_cast<uint8_t>(bndPort >> 8);
        buffer[portOffset + 1] = static_cast<uint8_t>(bndPort & 0xFF);
    }

    // Serialize to vector
    [[nodiscard]] std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> result(size());
        serialize(result.data());
        return result;
    }
};

CoroTask<void> handleSocks5Request(const std::shared_ptr<ClientContext2> clientCtx) {
    // Ensure buffer is ready for reading request
    clientCtx->buffer.resize(ClientContext2::kInitialBufferSize);

    // Read at least 5 bytes to determine request length
    size_t length = 0;
    while (length < 5) {
        const size_t read = co_await clientCtx->socket->read({
            clientCtx->buffer.data() + length, clientCtx->buffer.size() - length
        });
        if (read == 0) {
            throw std::runtime_error("Socket closed during SOCKS5 request");
        }
        length += read;
    }

    // Parse SOCKS5 request
    const auto req = Socks5Request::deserialize(clientCtx->buffer.data());
    if (req.rsv != 0) {
        throw std::runtime_error("Invalid SOCKS5 request: RSV must be 0");
    }

    if (req.version != Socks5::Version || req.cmd != Socks5::Cmd::Connect) {
        throw std::runtime_error("Unsupported SOCKS5 version or command");
    }

    [[maybe_unused]] ssize_t requestLen = 0;
    Endpoint targetEndpoint;

    switch (req.atyp) {
        case Socks5::Atyp::IpV4:
            if (length < 10) {
                // Need more bytes
                const size_t needed = 10 - length;
                const size_t read = co_await clientCtx->socket->read({
                    clientCtx->buffer.data() + length, clientCtx->buffer.size() - length
                });
                if (read < needed) {
                    throw std::runtime_error("Incomplete IPv4 SOCKS5 request");
                }
                length += read;
            } {
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                std::memcpy(&addr.sin_addr, &clientCtx->buffer[4], sizeof(in_addr));
                addr.sin_port = htons(static_cast<uint16_t>(clientCtx->buffer[8] << 8) | clientCtx->buffer[9]);
                targetEndpoint = Endpoint(addr);
            }
            requestLen = 10;
            break;

        case Socks5::Atyp::Domain: {
            const uint8_t domainLen = clientCtx->buffer[4];
            if (length < static_cast<size_t>(5 + domainLen + 2)) {
                const size_t needed = 5 + domainLen + 2 - length;
                const size_t read = co_await clientCtx->socket->read({
                    clientCtx->buffer.data() + length, clientCtx->buffer.size() - length
                });
                if (read < needed) {
                    throw std::runtime_error("Incomplete domain SOCKS5 request");
                }
                length += read;
            }
            std::string targetHost = std::string(reinterpret_cast<const char *>(&clientCtx->buffer[5]), domainLen);
            uint16_t targetPort = static_cast<uint16_t>(clientCtx->buffer[5 + domainLen] << 8) |
                                  clientCtx->buffer[5 + domainLen + 1];
            targetEndpoint = Endpoint(targetHost, targetPort);
            requestLen = 5 + domainLen + 2;
        }
        break;

        case Socks5::Atyp::IpV6:
            if (length < 22) {
                const size_t needed = 22 - length;
                const size_t read = co_await clientCtx->socket->read({
                    clientCtx->buffer.data() + length, clientCtx->buffer.size() - length
                });
                if (read < needed) {
                    throw std::runtime_error("Incomplete IPv6 SOCKS5 request");
                }
                length += read;
            } {
                sockaddr_in6 addr6{};
                addr6.sin6_family = AF_INET6;
                std::memcpy(&addr6.sin6_addr, &clientCtx->buffer[4], sizeof(in6_addr));
                addr6.sin6_port = htons(static_cast<uint16_t>(clientCtx->buffer[20] << 8) | clientCtx->buffer[21]);
                targetEndpoint = Endpoint(addr6);
            }
            requestLen = 22;
            break;

        default:
            throw std::runtime_error("Unsupported SOCKS5 address type");
    }

    // Store target information
    clientCtx->targetEndpoint = std::move(targetEndpoint);

    // Send success response (dummy IPv4 0.0.0.0)
    const auto response = Socks5Response::dummy(clientCtx->targetEndpoint.port());
    clientCtx->buffer = response.serialize();

    if (const size_t written = co_await clientCtx->socket->write({clientCtx->buffer.data(), clientCtx->buffer.size()});
        written != clientCtx->buffer.size()) {
        throw std::runtime_error("Failed to send SOCKS5 response");
    }

    // Transition to SSH_SOCKET_CONNECT state
    clientCtx->setState(ClientContext2::State::SSH_SOCKET_CONNECT);
    std::cout << "SOCKS5 request processed: " << clientCtx->targetEndpoint.toString() << '\n';
}

CoroTask<void> startMainLoop(const ProxyConfig config) {
    Socket serverSocket;
    serverSocket.setReusePort(true);
    std::cout << "listen port: " << config.listenPort + 1 << '\n';
    if (!serverSocket.bind(Endpoint(config.listenPort + 1))) {
        throw std::runtime_error("Failed to bind server socket");
    }
    std::unordered_map<Endpoint, std::shared_ptr<ClientContext2> > clients;
    while (true) {
        auto [socket, endpoint] = co_await serverSocket.listen();
        std::cout << "new socket ip: " << endpoint.ipStr() << ", port: " << endpoint.port() << '\n';
        auto client = std::make_shared<ClientContext2>(endpoint, socket,
                                                       std::vector<uint8_t>(ClientContext2::kInitialBufferSize));
        clients.try_emplace(endpoint, client);
        try {
            co_await handleSocks5Handshake(client);
            co_await handleSocks5Request(client);
            // For now, close connection after request processing
            client->closeSocket();
            clients.erase(endpoint);
        } catch (const std::exception &e) {
            std::cout << "Error handling client: " << e.what() << '\n';
            client->closeSocket();
            clients.erase(endpoint);
        }
    }
}

void SSHProxy::mainLoop(const std::stop_token &stopToken) {
    // Setup epoll
    if (setupEpoll() != ResultCode::Ok) {
        return;
    }

    log_d("SOCKS5 proxy started on port: {} via SSH: {}:{}\n",
          config.value().listenPort,
          config.value().ssh.host,
          config.value().ssh.port);
    log_d("Proxy started. Press Ctrl+C to stop...\n");

    const auto isStopRequested = [stopToken, &flag = stopSignalFlag] {
        return stopToken.stop_requested() || flag.load(std::memory_order_relaxed);
    };

#ifndef NDEBUG
    EpollScheduler sched(isStopRequested);
    const auto task = startMainLoop(config.value());
    std::cout << "start\n";
    task.start(sched);
    sched.run();
#endif

    while (!isStopRequested()) {
        // Setup local server
        if (!setupLocalServer()) {
            log_e("Failed to setup local server\n");
            break;
        }
        epollManager->add(serverFd, EPollManager::EPOLL_IN);

        while (serverFd != -1 && !isStopRequested()) {
            const int countFd = epollManager->wait(500);
            if (countFd == -1) {
                if (errno == EINTR) {
                    continue;
                }
                log_e("Failed epoll wait: {}\n", strerror(errno));
                break;
            }

            for (size_t i = 0; i < static_cast<size_t>(countFd); ++i) {
                const int fd = epollManager->getEvent(i).data.fd;
                const uint32_t eventMask = epollManager->getEvent(i).events;
                // log_d("{}, mask: {}\n", fd, eventMask);

                if (fd == serverFd) {
                    if (eventMask & EPollManager::EPOLL_IN) {
                        handleNewClientConnection();
                    }
                } else {
                    if (eventMask & EPollManager::EPOLL_IO) {
                        if (sshToClientSockets.contains(fd)) {
                            if (const auto &clientCtxOpt = getClientCtxBySshFd(fd)) {
                                switch (clientCtxOpt.value()->state) {
                                    case ClientContext::State::SSH_SERVER_CONNECTING:
                                    case ClientContext::State::SSH_SERVER_AUTHENTICATE:
                                    case ClientContext::State::SSH_CHANNEL_CREATING:
                                        setupSshConnection(clientCtxOpt.value());
                                        break;
                                    case ClientContext::State::FORWARDING:
                                        if (eventMask & EPollManager::EPOLL_IN) {
                                            handleSshRead(clientCtxOpt.value());
                                        } else {
                                            handleSshWrite(clientCtxOpt.value());
                                        }
                                        break;
                                    case ClientContext::State::CHANNEL_CLOSING:
                                        closeConnection(clientCtxOpt.value());
                                        break;
                                    default:
                                        log_e("Unexpected client state: {}\n",
                                              static_cast<int>(clientCtxOpt.value()->state));
                                        abort();
                                        break;
                                }
                            } else {
                                abort();
                            }
                        } else {
                            if (const auto clientCtxOpt = getClientCtxByFd(fd)) {
                                switch (clientCtxOpt.value()->state) {
                                    case ClientContext::State::HANDSHAKE:
                                    case ClientContext::State::REQUEST:
                                    case ClientContext::State::FORWARDING:
                                        if (eventMask & EPollManager::EPOLL_IN) {
                                            handleClientForRead(clientCtxOpt.value());
                                        } else {
                                            handleClientForWrite(clientCtxOpt.value());
                                        }
                                        break;
                                    default:
                                        break;
                                }
                            }
                        }
                    } else if (eventMask & EPollManager::EPOLL_ERR) {
                        log_e("{}, Client socket error/hangup\n", fd);
                        std::optional<std::shared_ptr<ClientContext> > clientCtx;
                        if (sshToClientSockets.contains(fd)) {
                            clientCtx = clients[sshToClientSockets[fd]];
                        } else if (clients.contains(fd)) {
                            clientCtx = clients[fd];
                        } else {
                            const auto it = std::ranges::find_if(sshSessionObjectPool, [fd](const auto &item) {
                                return item->fd == fd;
                            });
                            if (it != sshSessionObjectPool.end()) {
                                sshSessionObjectPool.erase(it);
                            }
                        }
                        if (clientCtx) {
                            closeConnection(clientCtx.value());
                        }
                    }
                }
            }
        }

        closeAllConnection();
        epollManager->remove(serverFd);
    }
    log_d("Proxy finished\n");
}

void SSHProxy::handleClientForRead(const std::shared_ptr<ClientContext> &clientCtx) {
    char buffer[BUFFER_SIZE];
    // Read all available data
    while (true) {
        const ssize_t bytesRead = recv(clientCtx->fd, buffer, sizeof(buffer), 0);
        log_v("{}, Client read bytes: {}, errno: {}\n", clientCtx->fd, bytesRead, errno);
        if (bytesRead < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            log_d("{}, Client read error: {}!\n", clientCtx->fd, errno);
            closeConnection(clientCtx);
            return;
        }
        if (bytesRead > 0) {
            clientCtx->readBuffer.insert(clientCtx->readBuffer.end(),
                                         buffer,
                                         buffer + bytesRead);
        }
        if (bytesRead == 0) {
            closeConnection(clientCtx);
            return;
        }
    }

    // Process data based on client state
    switch (clientCtx->state) {
        case ClientContext::State::HANDSHAKE:
            handleSocks5Handshake(clientCtx);
            break;
        case ClientContext::State::REQUEST:
            handleSocks5Request(clientCtx);
            break;
        case ClientContext::State::FORWARDING:
            handleSshWrite(clientCtx);
            break;
        default:
            abort();
            break;
    }
}

void SSHProxy::handleClientForWrite(const std::shared_ptr<ClientContext> &clientCtx) {
    if (!clientCtx->writeBuffer.empty()) {
        const ssize_t sent = send(clientCtx->fd,
                                  clientCtx->writeBuffer.data(),
                                  clientCtx->writeBuffer.size(),
                                  MSG_NOSIGNAL | MSG_DONTWAIT);
        if (sent > 0) {
            clientCtx->writeBuffer.erase(clientCtx->writeBuffer.begin(),
                                         clientCtx->writeBuffer.begin() + sent);

            if (!clientCtx->writeBuffer.empty()) {
                epollManager->modify(clientCtx->fd, EPollManager::EPOLL_ET | EPollManager::EPOLL_IO_ERR);
            } else {
                epollManager->modify(clientCtx->fd,
                                     EPollManager::EPOLL_IN | EPollManager::EPOLL_ET | EPollManager::EPOLL_ERR);
            }
        } else if (sent == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                epollManager->modify(clientCtx->fd, EPollManager::EPOLL_ET | EPollManager::EPOLL_IO_ERR);
            } else {
                log_d("{}, Failed to send data for client: {}\n", clientCtx->fd, strerror(errno));
                closeConnection(clientCtx);
            }
        }
    } else {
        epollManager->modify(clientCtx->fd,
                             EPollManager::EPOLL_IN | EPollManager::EPOLL_ET | EPollManager::EPOLL_ERR);
    }
}

void SSHProxy::handleSshRead(const std::shared_ptr<ClientContext> &clientCtx) {
    switch (sshRead(clientCtx)) {
        case ResultCode::Ok:
        case ResultCode::ErrAgain:
            break;
        case ResultCode::ErrIO:
        case ResultCode::ErrTimeout:
            closeConnection(clientCtx);
            break;
        default:
            abort();
            break;
    }
}

void SSHProxy::handleSshWrite(const std::shared_ptr<ClientContext> &clientCtx) {
    switch (sshWrite(clientCtx)) {
        case ResultCode::Ok:
        case ResultCode::ErrAgain:
            break;
        case ResultCode::ErrIO:
        case ResultCode::ErrTimeout:
            closeConnection(clientCtx);
            break;
        default:
            abort();
            break;
    }
}

void SSHProxy::handleNewClientConnection() {
    sockaddr_in clientAddr{};
    socklen_t clientLen = sizeof(clientAddr);

    const int clientFd = accept4(serverFd, reinterpret_cast<sockaddr *>(&clientAddr),
                                 &clientLen, SOCK_NONBLOCK);
    if (clientFd == -1) {
        log_d("{}, Failed to accept client connection!\n", clientFd);
        return;
    }

    auto clientCtx = std::make_shared<ClientContext>(clientFd);
    clientCtx->state = ClientContext::State::HANDSHAKE;

    if (const auto it = clients.find(clientFd); it != clients.end()) {
        abort();
    }

    clients[clientFd] = std::move(clientCtx);
    epollManager->add(clientFd, EPollManager::EPOLL_IO_ERR | EPOLLET);

    log_d("{}, New connection: {}:{}\n", clientFd, inet_ntoa(clientAddr.sin_addr),
          ntohs(clientAddr.sin_port));
}

void SSHProxy::handleSocks5Handshake(const std::shared_ptr<ClientContext> &clientCtx) {
    if (clientCtx->readBuffer.size() < 2) {
        return;
    }

    // Parse SOCKS5 handshake
    const uint8_t version = clientCtx->readBuffer[0];
    const uint8_t nmethods = clientCtx->readBuffer[1];

    if (version != Socks5::Version || clientCtx->readBuffer.size() < static_cast<size_t>(2 + nmethods)) {
        closeConnection(clientCtx);
        return;
    }

    // Send handshake response
    constexpr uint8_t response[] = {Socks5::Version, Socks5::Auth::NoAuth};
    if (send(clientCtx->fd, response, sizeof(response), MSG_NOSIGNAL) != sizeof(response)) {
        closeConnection(clientCtx);
        return;
    }

    // Remove processed data
    clientCtx->readBuffer.erase(clientCtx->readBuffer.begin(),
                                clientCtx->readBuffer.begin() + 2 + nmethods);

    clientCtx->state = ClientContext::State::REQUEST;
}

void SSHProxy::handleSocks5Request(const std::shared_ptr<ClientContext> &clientCtx) {
    if (clientCtx->readBuffer.size() < 5) {
        return;
    }

    // Parse SOCKS5 request
    const auto req = Socks5Request::deserialize(clientCtx->readBuffer.data());
    if (req.rsv != 0) {
        log_d("{}, Invalid SOCKS5 request: RSV must be 0\n", clientCtx->fd);
        closeConnection(clientCtx);
        return;
    }
    const uint8_t version = req.version;
    const uint8_t cmd = req.cmd;
    const uint8_t atyp = req.atyp;

    if (version != Socks5::Version || cmd != Socks5::Cmd::Connect) {
        log_d("{}, Unsupported socks5 version\n", clientCtx->fd);
        closeConnection(clientCtx);
        return;
    }

    ssize_t requestLen;
    std::string targetHost;
    std::uint16_t targetPort;

    switch (atyp) {
        case Socks5::Atyp::IpV4:
            if (clientCtx->readBuffer.size() < 10) {
                return;
            }
            char ipv4[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientCtx->readBuffer[4], ipv4, INET_ADDRSTRLEN);
            targetHost = ipv4;
            targetPort = static_cast<uint16_t>(clientCtx->readBuffer[8] << 8) | clientCtx->readBuffer[9];
            requestLen = 10;
            break;

        case Socks5::Atyp::Domain:
            if (clientCtx->readBuffer.size() < static_cast<size_t>(5 + clientCtx->readBuffer[4] + 2)) {
                return;
            }
            targetHost = std::string(reinterpret_cast<const char *>(&clientCtx->readBuffer[5]),
                                     clientCtx->readBuffer[4]);
            targetPort = static_cast<uint16_t>(clientCtx->readBuffer[5 + clientCtx->readBuffer[4]] << 8)
                         | clientCtx->readBuffer[5 + clientCtx->readBuffer[4] + 1];
            requestLen = 5 + clientCtx->readBuffer[4] + 2;
            break;

        case Socks5::Atyp::IpV6:
            // IPv6: 16 bytes address + 2 bytes port = 18 bytes + 4 header = 22 bytes total
            if (clientCtx->readBuffer.size() < 22) {
                return;
            }
            char ipv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &clientCtx->readBuffer[4], ipv6, INET6_ADDRSTRLEN);
            targetHost = ipv6;
            targetPort = static_cast<uint16_t>(clientCtx->readBuffer[20] << 8) | clientCtx->readBuffer[21];
            requestLen = 22;
            break;

        default:
            log_e("Unsupported address type: {}\n", static_cast<int>(atyp));
            closeConnection(clientCtx);
            return;
    }

    log_d("{}, Client request: {}:{}, (type: {})\n", clientCtx->fd, targetHost, targetPort, atyp);

    // Remove processed data
    clientCtx->readBuffer.erase(clientCtx->readBuffer.begin(),
                                clientCtx->readBuffer.begin() + requestLen);
    clientCtx->addr = {targetHost, targetPort};
    clientCtx->state = ClientContext::State::SSH_SERVER_CONNECTING;
    setupSshConnection(clientCtx);
}

ResultCode SSHProxy::createSshChannel(const std::shared_ptr<ClientContext> &clientCtx) {
    auto channel = clientCtx->sshContext->session->createChannel(clientCtx->addr);
    if (!channel.has_value()) {
        return channel.error();
    }
    log_v("{}, Create Ssh channel to: {}\n", clientCtx->fd, clientCtx->addr.toString());

    epollManager->modify(clientCtx->sshContext->session->fd,
                         EPollManager::EPOLL_IN | EPollManager::EPOLL_ET | EPollManager::EPOLL_ERR);
    clientCtx->sshContext->channel = channel.value();
    clientCtx->state = ClientContext::State::FORWARDING;
    clientCtx->requestTime = std::chrono::high_resolution_clock::now();

    // Send success response
    const auto response = Socks5Response::fromHost(clientCtx->addr.host, clientCtx->addr.port);
    clientCtx->writeBuffer = response.serialize();

    if (sendToClient(clientCtx) == ResultCode::ErrIO) {
        return ResultCode::ErrIO;
    }
    log_d("{}, Created SSH channel to: {}\n", clientCtx->fd, clientCtx->addr.toString());
    return ResultCode::Ok;
}

ResultCode SSHProxy::closeSshChannel(const std::shared_ptr<ClientContext> &clientCtx) {
    if (clientCtx->sshContext == nullptr) {
        return ResultCode::Ok;
    }
    if (clientCtx->sshContext->channel == nullptr) {
        return ResultCode::Ok;
    }
    return clientCtx->sshContext->channel->closeConnection();
}

std::optional<std::shared_ptr<ClientContext> > SSHProxy::getClientCtxBySshFd(const int sshFd) {
    const auto clientFdIt = sshToClientSockets.find(sshFd);
    if (clientFdIt == sshToClientSockets.end()) {
        return std::nullopt;
    }
    return getClientCtxByFd(clientFdIt->second);
}

std::optional<std::shared_ptr<ClientContext> > SSHProxy::getClientCtxByFd(const int clientFd) {
    const auto &clientCtxIt = clients.find(clientFd);
    if (clientCtxIt == clients.end()) {
        return std::nullopt;
    }
    return clientCtxIt->second;
}

void SSHProxy::closeConnection(const std::shared_ptr<ClientContext> &clientCtx) {
    switch (clientCtx->state) {
        case ClientContext::State::HANDSHAKE:
        case ClientContext::State::REQUEST:
        case ClientContext::State::SSH_SERVER_CONNECTING:
        case ClientContext::State::SSH_SERVER_AUTHENTICATE:
        case ClientContext::State::SSH_CHANNEL_CREATING:
        case ClientContext::State::FORWARDING:
            clientCtx->state = ClientContext::State::CHANNEL_CLOSING;
            break;
        case ClientContext::State::CHANNEL_CLOSING:
            break;
        default:
            abort();
            break;
    }

    if (clientCtx->sshContext == nullptr) {
        epollManager->remove(clientCtx->fd);
    } else if (closeSshChannel(clientCtx) == ResultCode::Ok) {
        sshToClientSockets.erase(clientCtx->sshContext->session->fd);
        clients.erase(clientCtx->fd);
        epollManager->remove(clientCtx->fd);
        epollManager->remove(clientCtx->sshContext->session->fd);
        log_d("{}, Closed connection. Address: {}, read: {} bytes, written: {} bytes\n", clientCtx->fd,
              clientCtx->addr.toString(),
              clientCtx->totalBytesRead,
              clientCtx->totalBytesWritten);
    }
}

ResultCode SSHProxy::handleSessionAuthenticateClient(const std::shared_ptr<ClientContext> &clientCtx) const {
    if (clientCtx->sshContext->session == nullptr) {
        abort();
    }

    if (clientCtx->sshContext->session->getState() == SSH2Session::State::HANDSHAKE
        && clientCtx->sshContext->session->handshake(clientCtx->sshContext->session->fd) == ResultCode::ErrAgain) {
        return ResultCode::ErrAgain;
    }

    if (clientCtx->sshContext->session->getState() == SSH2Session::State::AUTHENTICATE
        && clientCtx->sshContext->session->authenticate(config.value().ssh) == ResultCode::ErrAgain) {
        return ResultCode::ErrAgain;
    }

    clientCtx->sshContext->isAuthenticated = true;
    return ResultCode::Ok;
}

void SSHProxy::closeAllConnection() {
    // Close all file descriptors
    if (serverFd != -1) {
        close(serverFd);
        serverFd = -1;
    }

    for (const auto &socketFd: clients | std::views::keys) {
        close(socketFd);
    }
    clients.clear();
}
