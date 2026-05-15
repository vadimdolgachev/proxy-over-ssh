//
// Created by vadim on 28.01.2026.
//

#include <cerrno>
#include <chrono>
#include <libssh2.h>
#include <stdexcept>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "Logger.h"
#include "SessionPool.h"
#include "SshError.h"
#include "SshSocket.h"
#include "Types.h"

ResultCode SshSocket::handleLibSsh2Result(const int rc, const char *operation) {
    if (rc == LIBSSH2_ERROR_EAGAIN) {
        if (sessionHandle && sessionHandle->sshSession) {
            pendingDirections = sessionHandle->sshSession->blockDirections();
        } else {
            pendingDirections = LIBSSH2_SESSION_BLOCK_OUTBOUND;
        }
        return ResultCode::ErrAgain;
    }
    if (rc != 0) {
        sessionHandle = std::nullopt;
        SshError::logError(operation, rc);
        return SshError::libSsh2ToResultCode(rc);
    }
    pendingDirections = 0;
    return ResultCode::Ok;
}

ResultCode SshSocket::handleLibSsh2ChannelResult(const LIBSSH2_CHANNEL *const channel,
                                                 const char *operation,
                                                 const std::string &host) {
    if (channel == nullptr) {
        const int lastErr = libssh2_session_last_errno(sessionHandle->sshSession->raw());
        if (lastErr == LIBSSH2_ERROR_EAGAIN) {
            pendingDirections = sessionHandle->sshSession->blockDirections();
            return ResultCode::ErrAgain;
        }
        sessionHandle = std::nullopt;
        SshError::logError(operation, lastErr, host);
        return SshError::libSsh2ToResultCode(lastErr);
    }
    pendingDirections = 0;
    return ResultCode::Ok;
}

int SshSocket::getBlockDirections() const {
    if (pendingDirections != 0) {
        return pendingDirections;
    }
    if (sessionHandle && sessionHandle->sshSession) {
        return sessionHandle->sshSession->blockDirections();
    }
    return 0;
}

uint32_t SshSocket::computePollEvents(const int directions, const uint32_t defaultEvents) {
    uint32_t events = 0;
    if (directions & LIBSSH2_SESSION_BLOCK_INBOUND) {
        events |= EpollScheduler::PollIn;
    }
    if (directions & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
        events |= EpollScheduler::PollOut;
    }
    if (events == 0) {
        events = defaultEvents;
    }
    return events;
}

ResultCode SshSocket::tryConnectNonBlocking() {
    if (sessionPool != nullptr && sessionHandle == std::nullopt) {
        if (auto opt = sessionPool->acquire()) {
            sessionHandle = std::move(*opt);
            if (sessionHandle->tcpSocket != nullptr) {
                connectionState = State::SSH_AUTHENTICATED;
            } else {
                sessionHandle = std::nullopt;
            }
        }
    }

    while (connectionState != State::CHANNEL_CREATED) {
        const auto rc = advanceConnection();
        if (rc == ResultCode::ErrAgain) {
            return ResultCode::ErrAgain;
        }
        if (rc != ResultCode::Ok) {
            return rc;
        }
    }
    return ResultCode::Ok;
}

SshSocket::SshSocket(SSHConfig sshConfig_, const std::shared_ptr<SessionPool> &sessionPool_) :
    sessionPool(sessionPool_),
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
    if (sessionHandle == std::nullopt) {
        sessionHandle = SshSessionHandler{
            .sshSession = nullptr,
            .tcpSocket = std::make_unique<Socket>(),
            .lastUsed = std::chrono::steady_clock::now(),
        };
    }

    if (sessionHandle->tcpSocket == nullptr || sessionHandle->tcpSocket->fd() < 0) {
        return ResultCode::ErrIO;
    }

    const int fd = sessionHandle->tcpSocket->fd();
    auto [storage, len] = sshServerEndpoint.sockaddrStorage();

    if (const int rc = connect(fd, reinterpret_cast<const sockaddr *>(&storage), len); rc == 0) {
        connectionState = State::TCP_CONNECTED;
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
        connectionState = State::TCP_CONNECTED;
        return ResultCode::Ok;
    }

    return ResultCode::ErrIO;
}

ResultCode SshSocket::advanceConnection() {
    switch (connectionState) {
        case State::DISCONNECTED: {
            const auto rc = tryTcpConnect();
            if (rc == ResultCode::ErrAgain) {
                pendingDirections = LIBSSH2_SESSION_BLOCK_OUTBOUND;
                return ResultCode::ErrAgain;
            }
            connectionState = rc == ResultCode::Ok ? State::TCP_CONNECTED : State::ERROR;
            return rc;
        }
        case State::TCP_CONNECTED: {
            const auto rc = performHandshake();
            if (rc == ResultCode::Ok) {
                connectionState = State::SSH_HANDSHAKE;
            } else if (rc != ResultCode::ErrAgain) {
                connectionState = State::ERROR;
            }
            return rc;
        }
        case State::SSH_HANDSHAKE: {
            const auto rc = performAuthentication();
            if (rc == ResultCode::Ok) {
                connectionState = State::SSH_AUTHENTICATED;
            } else if (rc != ResultCode::ErrAgain) {
                connectionState = State::ERROR;
            }
            return rc;
        }
        case State::SSH_AUTHENTICATED: {
            const auto rc = createChannel();
            if (rc == ResultCode::Ok) {
                connectionState = State::CHANNEL_CREATED;
            } else if (rc != ResultCode::ErrAgain) {
                connectionState = State::ERROR;
            }
            return rc;
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
            return ResultCode::ErrUnknown;
        }
    }

    const int rc = sessionHandle->sshSession->handshake(sessionHandle->tcpSocket);
    return handleLibSsh2Result(rc, "performHandshake");
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

    return handleLibSsh2Result(rc, "performAuthentication");
}

ResultCode SshSocket::createChannel() {
    if (sessionHandle->sshSession == nullptr) {
        return ResultCode::ErrUnknown;
    }

    const auto host = targetEndpoint.host();
    const int port = targetEndpoint.port();

    auto *const channel = libssh2_channel_direct_tcpip_ex(sessionHandle->sshSession->raw(),
                                                               host.c_str(),
                                                               port,
                                                               "127.0.0.1",
                                                               0);
    const auto result = handleLibSsh2ChannelResult(channel, "createChannel", host);
    if (result == ResultCode::Ok) {
        libSsh2Channel = channel;
    }
    return result;
}

CoroTask<ResultCode> SshSocket::connectAsync(const Endpoint &targetEndpoint_, CancellationTokenOpt ct) {
    targetEndpoint = targetEndpoint_;

    while (true) {
        const auto rc = tryConnectNonBlocking();
        if (rc == ResultCode::Ok) {
            co_return ResultCode::Ok;
        }
        if (rc != ResultCode::ErrAgain) {
            co_return rc;
        }
        co_await SshConnectAwaiter{shared_from_this(), targetEndpoint, ct};
        if (ct && ct->isStopped()) {
            throw std::logic_error("SshSocket::connectAsync");
        }
    }
}

CoroTask<size_t> SshSocket::readAsync(std::span<uint8_t> buffer, CancellationTokenOpt ct) {
    while (true) {
        if (libSsh2Channel == nullptr) {
            co_return 0;
        }

        ssize_t n;
        bool eof;
        {
            std::lock_guard lock(sshMutex);
            n = libssh2_channel_read(libSsh2Channel,
                                     reinterpret_cast<char *>(buffer.data()),
                                     buffer.size());
            eof = n <= 0 && libssh2_channel_eof(libSsh2Channel) != 0;
            if (sessionHandle && sessionHandle->sshSession) {
                libssh2_keepalive_send(sessionHandle->sshSession->raw(), nullptr);
            }
        }

        if (n > 0) {
            co_return static_cast<size_t>(n);
        }

        if (eof || n == 0 || n == LIBSSH2_ERROR_CHANNEL_CLOSED) {
            co_return 0;
        }

        if (n == LIBSSH2_ERROR_EAGAIN) {
            co_await SshFdWaitAwaiter{shared_from_this(), ct};
            continue;
        }

        int sockErr = 0;
        socklen_t sockErrLen = sizeof(sockErr);
        getsockopt(fd(), SOL_SOCKET, SO_ERROR, &sockErr, &sockErrLen);
        throw std::runtime_error("SSH channel read error: " + std::to_string(n)
                                 + ", socket: " + std::to_string(sockErr)
                                 + " (" + std::strerror(sockErr) + ")");
    }
}

CoroTask<size_t> SshSocket::writeAsync(const std::span<const uint8_t> data, CancellationTokenOpt ct) {
    while (true) {
        if (libSsh2Channel == nullptr) {
            co_return 0;
        }

        ssize_t n;
        bool eof;
        {
            std::lock_guard lock(sshMutex);
            n = libssh2_channel_write(libSsh2Channel,
                                      reinterpret_cast<const char *>(data.data()),
                                      data.size());
            eof = n == LIBSSH2_ERROR_EAGAIN && libssh2_channel_eof(libSsh2Channel) != 0;
            if (sessionHandle && sessionHandle->sshSession) {
                libssh2_keepalive_send(sessionHandle->sshSession->raw(), nullptr);
            }
        }

        if (n > 0) {
            co_return static_cast<size_t>(n);
        }

        if (eof || n == 0 || n == LIBSSH2_ERROR_CHANNEL_CLOSED) {
            co_return 0;
        }

        if (n == LIBSSH2_ERROR_EAGAIN) {
            co_await SshFdWaitAwaiter{shared_from_this(), ct};
            continue;
        }

        if (n < 0) {
            int sockErr = 0;
            socklen_t sockErrLen = sizeof(sockErr);
            getsockopt(fd(), SOL_SOCKET, SO_ERROR, &sockErr, &sockErrLen);
            throw std::runtime_error("SSH channel write error: " + std::to_string(n)
                                     + ", socket: " + std::to_string(sockErr)
                                     + " (" + std::strerror(sockErr) + ")");
        }

        co_return 0;
    }
}

int SshSocket::fd() const noexcept {
    if (sessionHandle != std::nullopt && sessionHandle->tcpSocket != nullptr) {
        return sessionHandle->tcpSocket->fd();
    }
    return -1;
}

bool SshSocket::isEof() const noexcept {
    if (libSsh2Channel == nullptr) {
        return true;
    }
    const int eof = libssh2_channel_eof(libSsh2Channel);
    return eof != 0;
}


void SshSocket::close() noexcept {
    if (libSsh2Channel != nullptr) {
        std::lock_guard lock(sshMutex);
        libssh2_channel_close(libSsh2Channel);
        libssh2_channel_free(libSsh2Channel);
        libSsh2Channel = nullptr;
    }

    if (sessionHandle == std::nullopt) {
        return;
    }

    if (sessionPool != nullptr && connectionState != State::ERROR) {
        sessionPool->release(std::move(sessionHandle.value()));
    } else {
        if (sessionHandle->tcpSocket != nullptr) {
            shutdown(sessionHandle->tcpSocket->fd(), SHUT_RDWR);
        }
        if (sessionPool != nullptr) {
            sessionPool->invalidate(*sessionHandle);
        }
    }

    sessionHandle = std::nullopt;
    connectionState = State::DISCONNECTED;
    pendingDirections = 0;
}

SshSocketAwaiterBase::SshSocketAwaiterBase(std::shared_ptr<SshSocket> socket_,
                                           const CancellationTokenOpt &cancellationToken_) :
    socket(std::move(socket_)),
    cancellationToken(cancellationToken_) {
}

uint32_t SshSocketAwaiterBase::computePollEvents(const uint32_t defaultEvents) const {
    const int directions = socket->getBlockDirections();
    return SshSocket::computePollEvents(directions, defaultEvents);
}

void SshSocketAwaiterBase::onSuspend(const std::coroutine_handle<> h, const uint32_t defaultEvents) {
    assert(this->getScheduler() != nullptr);
    handle = h;
    uint32_t events = computePollEvents(defaultEvents);
    events |= EpollScheduler::PollErr | EpollScheduler::PollHUp;
    this->getScheduler()->add(events, socket->fd(), h);
    if (cancellationToken) {
        this->getScheduler()->add(EpollScheduler::PollIn, cancellationToken->getFd(), h);
    }
}

void SshSocketAwaiterBase::onResume() {
    if (cancellationToken && handle) {
        this->getScheduler()->remove(cancellationToken->getFd(), handle);
    }
    if (cancellationToken && cancellationToken->isStopped()) {
        cancellationToken->drain();
        throw CancellationTokenException();
    }
}

SshConnectAwaiter::SshConnectAwaiter(std::shared_ptr<SshSocket> socket_,
                                     Endpoint targetEndpoint_,
                                     const CancellationTokenOpt &cancellationToken_) :
    SshSocketAwaiterBase(std::move(socket_), cancellationToken_),
    targetEndpoint(std::move(targetEndpoint_)) {
}

bool SshConnectAwaiter::await_ready() const noexcept {
    if (socket->connectionState == SshSocket::State::CHANNEL_CREATED) {
        return true;
    }

    if (socket->pendingDirections != 0) {
        return false;
    }

    const auto rc = socket->tryConnectNonBlocking();
    if (rc == ResultCode::ErrAgain) {
        return false;
    }
    if (rc != ResultCode::Ok) {
        connectErrno = static_cast<int>(rc);
        return true;
    }
    return true;
}

void SshConnectAwaiter::await_suspend(const std::coroutine_handle<> h) {
    onSuspend(h, EpollScheduler::PollIn | EpollScheduler::PollRdHUp);
}

void SshConnectAwaiter::await_resume() {
    onResume();
    if (connectErrno != 0) {
        const auto rc = static_cast<ResultCode>(connectErrno);
        throw std::runtime_error("SSH connection failed: " + std::string(SshError::toString(rc)));
    }
}

SshFdWaitAwaiter::SshFdWaitAwaiter(std::shared_ptr<SshSocket> socket_,
                                   const CancellationTokenOpt &cancellationToken_) :
    SshSocketAwaiterBase(std::move(socket_), cancellationToken_) {
}

bool SshFdWaitAwaiter::await_ready() const noexcept {
    if (cancellationToken && cancellationToken->isStopped()) {
        return true;
    }
    return false;
}

void SshFdWaitAwaiter::await_suspend(const std::coroutine_handle<> h) {
    onSuspend(h, EpollScheduler::PollIn);
}

void SshFdWaitAwaiter::await_resume() {
    onResume();
}
