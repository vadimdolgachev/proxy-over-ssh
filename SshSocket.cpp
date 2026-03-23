//
// Created by vadim on 28.01.2026.
//

#include <libssh2.h>
#include <stdexcept>
#include <utility>
#include <cerrno>
#include <chrono>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "SshSocket.h"
#include "Logger.h"
#include "Types.h"
#include "SessionPool.h"

namespace {
    std::string resultCodeToString(const ResultCode rc) {
        switch (rc) {
            case ResultCode::ErrAgain: return "ErrAgain";
            case ResultCode::ErrIO: return "ErrIO";
            case ResultCode::ErrTimeout: return "ErrTimeout";
            case ResultCode::ErrInvalidPrivateKey: return "ErrInvalidPrivateKey";
            case ResultCode::ErrUnknown: return "ErrUnknown";
            default: return "Unknown ResultCode";
        }
    }
}

SshSocket::SshSocket(SSHConfig sshConfig_, const std::shared_ptr<SessionPool> &sessionPool_)
    : sessionPool(sessionPool_),
      sshConfig(std::move(sshConfig_)) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(sshConfig.port);

    if (inet_pton(AF_INET, sshConfig.host.c_str(), &addr.sin_addr) == 1) {
        sshServerEndpoint = Endpoint(addr);
    } else {
        sockaddr_in6 addr6{};
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(sshConfig.port);
        if (inet_pton(AF_INET6, sshConfig.host.c_str(), &addr6.sin6_addr) == 1) {
            sshServerEndpoint = Endpoint(addr6);
        } else {
            throw std::runtime_error("SSH server host must be an IP address: " + sshConfig.host);
        }
    }
}

SshSocket::~SshSocket() {
    close();
}

ResultCode SshSocket::tryTcpConnect() {
    if (sessionPool && sessionHandle == std::nullopt) {
        sessionHandle = sessionPool->acquire();
        if (sessionHandle && sessionHandle->tcpSocket) {
            state = State::SSH_AUTHENTICATED;
            return ResultCode::Ok;
        }
    }

    if (sessionHandle == std::nullopt) {
        sessionHandle = SshSessionHandler{
            .sshSession = nullptr,
            .tcpSocket = std::make_unique<Socket>(),
            .lastUsed = std::chrono::steady_clock::now(),
        };
    }

    if (!sessionHandle->tcpSocket || sessionHandle->tcpSocket->fd() < 0) {
        return ResultCode::ErrIO;
    }

    const int fd = sessionHandle->tcpSocket->fd();
    auto [storage, len] = sshServerEndpoint.sockaddrStorage();

    if (const int rc = ::connect(fd, reinterpret_cast<const sockaddr *>(&storage), len);
        rc == 0) {
        state = State::TCP_CONNECTED;
        return ResultCode::Ok;
    }

    const int err = errno;
    if (err == EINPROGRESS || err == EALREADY) {
        return ResultCode::ErrAgain;
    }

    if (err == EISCONN) {
        int sockErr = 0;
        socklen_t sockErrLen = sizeof(sockErr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockErr, &sockErrLen) < 0) {
            return ResultCode::ErrIO;
        }
        if (sockErr != 0) {
            return ResultCode::ErrIO;
        }
        state = State::TCP_CONNECTED;
        return ResultCode::Ok;
    }

    return ResultCode::ErrIO;
}

ResultCode SshSocket::advanceConnection() {
    switch (state) {
        case State::DISCONNECTED: {
            const auto rc = tryTcpConnect();
            if (rc == ResultCode::ErrAgain) {
                pendingDirections = LIBSSH2_SESSION_BLOCK_OUTBOUND;
                return ResultCode::ErrAgain;
            }
            return rc;
        }
        case State::TCP_CONNECTED: {
            return performHandshake();
        }
        case State::SSH_HANDSHAKE: {
            return performAuthentication();
        }
        case State::SSH_AUTHENTICATED: {
            return createChannel();
        }
        case State::CHANNEL_CREATED:
            return ResultCode::Ok;
        case State::ERROR:
            return ResultCode::ErrUnknown;
    }
    return ResultCode::ErrUnknown;
}

ResultCode SshSocket::performHandshake() {
    if (sessionHandle->sshSession == nullptr) {
        try {
            sessionHandle->sshSession = std::make_unique<SshSession>();
        } catch (const std::exception &e) {
            state = State::ERROR;
            return ResultCode::ErrUnknown;
        }
    }

    const int rc = sessionHandle->sshSession->handshake(sessionHandle->tcpSocket);
    if (rc == LIBSSH2_ERROR_EAGAIN) {
        const int direction = sessionHandle->sshSession->blockDirections();
        pendingDirections = direction;
        return ResultCode::ErrAgain;
    }

    if (rc != 0) {
        sessionHandle = std::nullopt;
        std::cout << "ERROR: performHandshake\n";
        state = State::ERROR;
        return ResultCode::ErrUnknown;
    }

    state = State::SSH_HANDSHAKE;
    pendingDirections = 0;
    return ResultCode::Ok;
}

ResultCode SshSocket::performAuthentication() {
    if (sessionHandle->sshSession == nullptr) {
        return ResultCode::ErrUnknown;
    }

    int rc;
    if (sshConfig.privateKeyData.has_value()) {
        rc = libssh2_userauth_publickey_frommemory(sessionHandle->sshSession->raw(),
                                                   sshConfig.username.c_str(),
                                                   sshConfig.username.length(),
                                                   nullptr,
                                                   0,
                                                   sshConfig.privateKeyData.value().c_str(),
                                                   sshConfig.privateKeyData.value().length(),
                                                   nullptr);
    } else if (sshConfig.privateKeyPath.has_value()) {
        rc = libssh2_userauth_publickey_fromfile_ex(sessionHandle->sshSession->raw(),
                                                    sshConfig.username.c_str(),
                                                    static_cast<unsigned int>(sshConfig.username.length()),
                                                    nullptr,
                                                    sshConfig.privateKeyPath.value().c_str(),
                                                    nullptr);
    } else {
        return ResultCode::ErrInvalidPrivateKey;
    }

    if (rc == LIBSSH2_ERROR_EAGAIN) {
        const int direction = sessionHandle->sshSession->blockDirections();
        pendingDirections = direction;
        return ResultCode::ErrAgain;
    }

    if (rc != 0) {
        sessionHandle = std::nullopt;
        std::cout << "ERROR: performAuthentication\n";
        state = State::ERROR;
        return ResultCode::ErrUnknown;
    }

    state = State::SSH_AUTHENTICATED;
    pendingDirections = 0;
    return ResultCode::Ok;
}

ResultCode SshSocket::createChannel() {
    if (!sessionHandle->sshSession) {
        return ResultCode::ErrUnknown;
    }

    const auto host = targetEndpoint.host();
    const int port = targetEndpoint.port();

    libssh2Channel = libssh2_channel_direct_tcpip_ex(sessionHandle->sshSession->raw(),
                                                     host.c_str(),
                                                     port,
                                                     "::1",
                                                     0);
    if (libssh2Channel == nullptr) {
        const int lastErr = libssh2_session_last_errno(sessionHandle->sshSession->raw());
        if (
            lastErr == LIBSSH2_ERROR_EAGAIN) {
            const int direction = sessionHandle->sshSession->blockDirections();
            pendingDirections = direction;
            return ResultCode::ErrAgain;
        }

        sessionHandle = std::nullopt;
        std::cout << "ERROR: createChannel lastErr=" << lastErr << ", host=" << host << "\n";
        state = State::ERROR;
        return ResultCode::ErrIO;
    }

    state = State::CHANNEL_CREATED;
    pendingDirections = 0;
    return ResultCode::Ok;
}

SshConnectAwaiter SshSocket::connect(const Endpoint &targetEndpoint_) {
    targetEndpoint = targetEndpoint_;
    return {shared_from_this(), targetEndpoint};
}

CoroTask<ResultCode> SshSocket::connectAsync(const Endpoint &targetEndpoint_) {
    targetEndpoint = targetEndpoint_;

    while (state != State::CHANNEL_CREATED) {
        const auto rc = advanceConnection();
        if (rc == ResultCode::ErrAgain) {
            SshConnectAwaiter awaiter{shared_from_this(), targetEndpoint};
            co_await awaiter;
            continue;
        }
        if (rc != ResultCode::Ok) {
            co_return rc;
        }
    }
    co_return ResultCode::Ok;
}

SshReadAwaiter SshSocket::read(std::span<unsigned char> buffer) {
    return {shared_from_this(), buffer};
}

SshWriteAwaiter SshSocket::write(std::span<unsigned char> buffer) {
    return {shared_from_this(), buffer};
}

CoroTask<size_t> SshSocket::readAsync(std::span<uint8_t> buffer) {
    co_return co_await SshReadAwaiter(shared_from_this(),
                                      std::span(buffer.data(), buffer.size()));
}

CoroTask<size_t> SshSocket::writeAsync(std::span<const uint8_t> data) {
    co_return co_await SshWriteAwaiter(shared_from_this(),
                                       std::span(const_cast<unsigned char *>(data.data()), data.size()));
}

int SshSocket::fd() const noexcept {
    if (sessionHandle->tcpSocket) {
        return sessionHandle->tcpSocket->fd();
    }
    return -1;
}

bool SshSocket::isEof() const noexcept {
    if (libssh2Channel == nullptr) {
        return true;
    }
    const int eof = libssh2_channel_eof(libssh2Channel);
    return eof != 0;
}


void SshSocket::close() noexcept {
    std::cout << "SshSocket::close libssh2Channel: " << libssh2Channel << "\n" << std::endl;
    std::cout << "SshSocket::close sessionHandle: " << sessionHandle.has_value() << "\n" << std::endl;
    std::cout << "SshSocket::close state: " << static_cast<int>(state) << "\n" << std::endl;
    if (libssh2Channel != nullptr) {
        libssh2_channel_close(libssh2Channel);
        libssh2_channel_free(libssh2Channel);
        libssh2Channel = nullptr;
    }

    if (sessionPool && sessionHandle) {
        if (state != State::ERROR) {
            sessionPool->release(std::move(sessionHandle.value()));
            log_v("SshSocket: Returned session to pool\n");
        } else {
            sessionPool->invalidate(*sessionHandle);
            log_v("SshSocket: Invalidated session from pool due to error\n");
        }
    }

    sessionHandle = std::nullopt;
    state = State::DISCONNECTED;
    pendingDirections = 0;
}

SshConnectAwaiter::SshConnectAwaiter(std::shared_ptr<SshSocket> sshSocket_, Endpoint targetEndpoint_)
    : sshSocket(std::move(sshSocket_)),
      targetEndpoint(std::move(targetEndpoint_)) {
}

bool SshConnectAwaiter::await_ready() const noexcept {
    if (sshSocket->state == SshSocket::State::CHANNEL_CREATED) {
        return true;
    }

    if (sshSocket->pendingDirections != 0) {
        return false;
    }

    // Try to advance connection as far as possible without blocking
    while (true) {
        const auto rc = sshSocket->advanceConnection();

        if (rc == ResultCode::ErrAgain) {
            return false;
        }

        if (rc != ResultCode::Ok) {
            connectErrno = static_cast<int>(rc);
            return true; // Will throw in await_resume
        }

        if (sshSocket->state == SshSocket::State::CHANNEL_CREATED) {
            // Fully connected
            return true;
        }

        // State advanced but not yet fully connected, continue loop
        // (e.g., TCP_CONNECTED -> SSH_HANDSHAKE -> SSH_AUTHENTICATED -> CHANNEL_CREATED)
    }
}

void SshConnectAwaiter::await_suspend(std::coroutine_handle<> h) {
    if (this->getScheduler() == nullptr) {
        throw std::runtime_error("No scheduler set for SshConnectAwaiter");
    }

    uint32_t events = 0;
    if (sshSocket->pendingDirections & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
        events |= EpollScheduler::PollEvents::EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    }
    if (sshSocket->pendingDirections & LIBSSH2_SESSION_BLOCK_INBOUND) {
        events |= EpollScheduler::PollEvents::EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    }

    if (events == 0) {
        events = EpollScheduler::PollEvents::EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    }

    this->getScheduler()->add(events, sshSocket->fd(), h);
}

void SshConnectAwaiter::await_resume() {
    if (connectErrno != 0) {
        const auto rc = static_cast<ResultCode>(connectErrno);
        throw std::runtime_error("SSH connection failed: " + resultCodeToString(rc));
    }
}

SshReadAwaiter::SshReadAwaiter(std::shared_ptr<SshSocket> sshSocket_,
                               const std::span<unsigned char> buffer_) : sshSocket(std::move(sshSocket_)),
                                                                         buffer(buffer_),
                                                                         startTime(std::chrono::steady_clock::now()) {
}

bool SshReadAwaiter::await_ready() const noexcept {
    if (!sshSocket->sessionHandle || !sshSocket->sessionHandle->sshSession) {
        peekErrno = EINVAL;
        return true;
    }

    if (std::chrono::steady_clock::now() - startTime > timeout) {
        peekEof = true;
        return true;
    }

    const ssize_t n = libssh2_channel_read(sshSocket->libssh2Channel,
                                           reinterpret_cast<char*>(buffer.data()),
                                           buffer.size());
    if (n > 0) {
        peekResult = static_cast<size_t>(n);
        return true;
    }

    if (n == 0) {
        peekEof = true;
        return true;
    }

    if (n == LIBSSH2_ERROR_EAGAIN) {
        if (sshSocket->libssh2Channel && libssh2_channel_eof(sshSocket->libssh2Channel)) {
            peekEof = true;
            return true;
        }
        return false;
    }

    if (n == LIBSSH2_ERROR_CHANNEL_CLOSED) {
        peekEof = true;
        return true;
    }

    peekErrno = static_cast<int>(-n);
    return true;
}

void SshReadAwaiter::await_suspend(const std::coroutine_handle<> h) {
    // Determine which events to wait for based on libssh2's direction hint
    uint32_t events = 0;
    if (sshSocket->sessionHandle && sshSocket->sessionHandle->sshSession) {
        const int directions = sshSocket->sessionHandle->sshSession->blockDirections();
        if (directions & LIBSSH2_SESSION_BLOCK_INBOUND) {
            events |= EpollScheduler::PollEvents::EPOLLIN;
        }
        if (directions & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
            events |= EpollScheduler::PollEvents::EPOLLOUT;
        }
    }

    if (events == 0) {
        events = EpollScheduler::PollEvents::EPOLLIN;
    }

    events |= EpollScheduler::PollEvents::EPOLLHUP | EpollScheduler::PollEvents::EPOLLERR;
    this->getScheduler()->add(events, sshSocket->fd(), h);
}

size_t SshReadAwaiter::await_resume() {
    if (peekErrno != 0) {
        throw std::system_error(peekErrno, std::system_category(), "SSH read failed");
    }
    if (peekEof) {
        return 0;
    }
    if (peekResult.has_value()) {
        return *peekResult;
    }

    if (!sshSocket->libssh2Channel) {
        throw std::runtime_error("SSH channel not created");
    }

    const ssize_t n = libssh2_channel_read(sshSocket->libssh2Channel,
                                           reinterpret_cast<char*>(buffer.data()),
                                           buffer.size());

    if (n > 0) {
        return static_cast<size_t>(n);
    }
    if (n == 0) {
        return 0;
    }

    if (n == LIBSSH2_ERROR_EAGAIN) {
        if (libssh2_channel_eof(sshSocket->libssh2Channel) != 0) {
            return 0;
        }
        return 0;
    }

    if (n == LIBSSH2_ERROR_CHANNEL_CLOSED) {
        return 0;
    }

    throw std::runtime_error("SSH channel read error: " + std::to_string(n));
}

SshWriteAwaiter::SshWriteAwaiter(std::shared_ptr<SshSocket> sshSocket_, std::span<unsigned char> buffer_)
    : sshSocket(std::move(sshSocket_)), buffer(buffer_) {
}

bool SshWriteAwaiter::await_ready() const noexcept {
    if (!sshSocket->sessionHandle || !sshSocket->sessionHandle->sshSession) {
        pollErrno = EINVAL;
        pollError = true;
        return true;
    }

    // Try non-blocking write
    const ssize_t n = libssh2_channel_write(sshSocket->libssh2Channel,
                                            reinterpret_cast<const char*>(buffer.data()),
                                            buffer.size());
    if (n >= 0) {
        // Data written immediately
        pollResult = static_cast<size_t>(n);
        return true;
    }

    if (n == LIBSSH2_ERROR_EAGAIN) {
        return false;
    }

    if (n == LIBSSH2_ERROR_CHANNEL_CLOSED) {
        pollResult = 0;
        return true;
    }

    pollErrno = static_cast<int>(-n);
    pollError = true;
    return true;
}

void SshWriteAwaiter::await_suspend(const std::coroutine_handle<> h) {
    if (this->getScheduler() == nullptr) {
        throw std::runtime_error("No scheduler set for SshWriteAwaiter");
    }

    uint32_t events = 0;
    if (sshSocket->sessionHandle && sshSocket->sessionHandle->sshSession) {
        const int directions = sshSocket->sessionHandle->sshSession->blockDirections();
        if (directions & LIBSSH2_SESSION_BLOCK_INBOUND) {
            events |= EpollScheduler::PollEvents::EPOLLIN;
        }
        if (directions & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
            events |= EpollScheduler::PollEvents::EPOLLOUT;
        }
    }

    if (events == 0) {
        events = EpollScheduler::PollEvents::EPOLLOUT;
    }
    events |= EpollScheduler::PollEvents::EPOLLHUP | EpollScheduler::PollEvents::EPOLLERR;

    this->getScheduler()->add(events, sshSocket->fd(), h);
}

size_t SshWriteAwaiter::await_resume() {
    if (pollError) {
        throw std::system_error(pollErrno, std::system_category(), "SSH write failed");
    }
    if (pollResult.has_value()) {
        return *pollResult;
    }

    if (!sshSocket->libssh2Channel) {
        throw std::runtime_error("SSH channel not created");
    }

    const ssize_t n = libssh2_channel_write(sshSocket->libssh2Channel,
                                            reinterpret_cast<const char*>(buffer.data()),
                                            buffer.size());
    if (n >= 0) {
        return static_cast<size_t>(n);
    }

    if (n == LIBSSH2_ERROR_EAGAIN) {
        return 0;
    }

    if (n == LIBSSH2_ERROR_CHANNEL_CLOSED) {
        return 0;
    }

    throw std::runtime_error("SSH channel write error: " + std::to_string(n));
}
