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

uint32_t SshSocket::getPollEvents(const uint32_t defaultEvents) const {
    std::lock_guard lock(sshMutex);
    if (pendingDirections != 0) {
        return computePollEvents(pendingDirections, defaultEvents);
    }
    if (sessionHandle && sessionHandle->sshSession) {
        return computePollEvents(sessionHandle->sshSession->blockDirections(), defaultEvents);
    }
    return defaultEvents;
}

uint32_t SshSocket::computePollEvents(const int directions, const uint32_t defaultEvents) noexcept {
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
    const auto fingerprint = SshHostKey::parseSha256Fingerprint(sshConfig.hostKeySha256);
    if (!fingerprint) {
        throw std::invalid_argument(fingerprint.error());
    }
    expectedHostKeySha256 = *fingerprint;

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
            const auto rc = verifyHostKey();
            if (rc == ResultCode::Ok) {
                connectionState = State::SSH_HOST_VERIFIED;
            } else {
                connectionState = State::ERROR;
            }
            return rc;
        }
        case State::SSH_HOST_VERIFIED: {
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
    std::lock_guard lock(sshMutex);
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

ResultCode SshSocket::verifyHostKey() {
    std::lock_guard lock(sshMutex);
    if (!sessionHandle || sessionHandle->sshSession == nullptr) {
        return ResultCode::ErrHostKeyVerification;
    }

    size_t hostKeySize = 0;
    int hostKeyType = 0;
    if (const char *const hostKey =
                libssh2_session_hostkey(sessionHandle->sshSession->raw(), &hostKeySize, &hostKeyType);
        hostKey == nullptr || hostKeySize == 0 ||
        !SshHostKey::matchesSha256(std::span{reinterpret_cast<const std::uint8_t *>(hostKey), hostKeySize},
                                   expectedHostKeySha256)) {
        log_e("SSH host-key verification failed for {}:{}\n", sshConfig.host, sshConfig.port);
        return ResultCode::ErrHostKeyVerification;
    }
    return ResultCode::Ok;
}

ResultCode SshSocket::performAuthentication() {
    std::lock_guard lock(sshMutex);
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
    std::lock_guard lock(sshMutex);
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
        ssize_t n;
        bool eof;
        uint32_t waitEvents = EpollScheduler::PollIn;
        {
            std::lock_guard lock(sshMutex);
            if (libSsh2Channel == nullptr) {
                co_return 0;
            }
            n = libssh2_channel_read(libSsh2Channel,
                                     reinterpret_cast<char *>(buffer.data()),
                                     buffer.size());
            eof = n <= 0 && libssh2_channel_eof(libSsh2Channel) != 0;
            if (n == LIBSSH2_ERROR_EAGAIN && sessionHandle && sessionHandle->sshSession) {
                waitEvents = computePollEvents(sessionHandle->sshSession->blockDirections(),
                                               EpollScheduler::PollIn);
            } else if (n > 0 && sessionHandle && sessionHandle->sshSession) {
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
            co_await SshFdWaitAwaiter{shared_from_this(), ct, waitEvents};
            continue;
        }

        {
            std::lock_guard lock(sshMutex);
            connectionState = State::ERROR;
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
        ssize_t n;
        bool eof;
        uint32_t waitEvents = EpollScheduler::PollOut;
        {
            std::lock_guard lock(sshMutex);
            if (libSsh2Channel == nullptr) {
                co_return 0;
            }
            n = libssh2_channel_write(libSsh2Channel,
                                      reinterpret_cast<const char *>(data.data()),
                                      data.size());
            eof = n == LIBSSH2_ERROR_EAGAIN && libssh2_channel_eof(libSsh2Channel) != 0;
            if (n == LIBSSH2_ERROR_EAGAIN && sessionHandle && sessionHandle->sshSession) {
                waitEvents = computePollEvents(sessionHandle->sshSession->blockDirections(),
                                               EpollScheduler::PollOut);
            } else if (n > 0 && sessionHandle && sessionHandle->sshSession) {
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
            co_await SshFdWaitAwaiter{shared_from_this(), ct, waitEvents};
            continue;
        }

        {
            std::lock_guard lock(sshMutex);
            connectionState = State::ERROR;
        }

        int sockErr = 0;
        socklen_t sockErrLen = sizeof(sockErr);
        getsockopt(fd(), SOL_SOCKET, SO_ERROR, &sockErr, &sockErrLen);
        throw std::runtime_error("SSH channel write error: " + std::to_string(n)
                                 + ", socket: " + std::to_string(sockErr)
                                 + " (" + std::strerror(sockErr) + ")");
    }
}

int SshSocket::fd() const noexcept {
    try {
        std::lock_guard lock(sshMutex);
        if (sessionHandle != std::nullopt && sessionHandle->tcpSocket != nullptr) {
            return sessionHandle->tcpSocket->fd();
        }
    } catch (...) {
    }
    return -1;
}

bool SshSocket::isEof() const noexcept {
    try {
        std::lock_guard lock(sshMutex);
        if (libSsh2Channel == nullptr) {
            return true;
        }
        return libssh2_channel_eof(libSsh2Channel) != 0;
    } catch (...) {
        return true;
    }
}


void SshSocket::close() noexcept {
    std::optional<SshSessionHandler> handleToRelease;
    bool reusable = false;
    try {
        std::lock_guard lock(sshMutex);
        reusable = connectionState == State::CHANNEL_CREATED;
        if (libSsh2Channel != nullptr) {
            const int closeResult = libssh2_channel_close(libSsh2Channel);
            const int freeResult = libssh2_channel_free(libSsh2Channel);
            reusable = reusable && closeResult == 0 && freeResult == 0;
            libSsh2Channel = nullptr;
        }

        if (sessionHandle) {
            handleToRelease = std::move(*sessionHandle);
            sessionHandle.reset();
        }
        connectionState = State::DISCONNECTED;
        pendingDirections = 0;
    } catch (...) {
        reusable = false;
        libSsh2Channel = nullptr;
        try {
            if (sessionHandle) {
                handleToRelease = std::move(*sessionHandle);
                sessionHandle.reset();
            }
        } catch (...) {
        }
        connectionState = State::DISCONNECTED;
        pendingDirections = 0;
    }

    if (!handleToRelease) {
        return;
    }
    if (reusable && sessionPool != nullptr) {
        std::ignore = sessionPool->release(std::move(*handleToRelease));
        return;
    }
    if (handleToRelease->tcpSocket != nullptr) {
        shutdown(handleToRelease->tcpSocket->fd(), SHUT_RDWR);
    }
}

SshSocketAwaiterBase::SshSocketAwaiterBase(std::shared_ptr<SshSocket> socket_,
                                           const CancellationTokenOpt &cancellationToken_) :
    socket(std::move(socket_)),
    cancellationToken(cancellationToken_) {
}

void SshSocketAwaiterBase::onSuspend(const std::coroutine_handle<> h, uint32_t events) {
    assert(getScheduler() != nullptr);
    handle = h;
    events |= EpollScheduler::PollErr | EpollScheduler::PollHUp;
    bool cancellationRegistered = false;
    if (cancellationToken && cancellationToken->isStopped()) {
        throw CancellationTokenException();
    }
    try {
        if (cancellationToken) {
            getScheduler()->add(EpollScheduler::PollIn, cancellationToken->getFd(), h);
            cancellationRegistered = true;
        }
        getScheduler()->add(events, socket->fd(), h);
    } catch (...) {
        getScheduler()->rollbackAdd(socket->fd(), h);
        if (cancellationRegistered) {
            getScheduler()->rollbackAdd(cancellationToken->getFd(), h);
        }
        handle = nullptr;
        throw;
    }
}

void SshSocketAwaiterBase::onResume() {
    if (handle) {
        getScheduler()->rollbackAdd(socket->fd(), handle);
        if (cancellationToken) {
            getScheduler()->rollbackAdd(cancellationToken->getFd(), handle);
        }
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

bool SshConnectAwaiter::await_ready() const {
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
    onSuspend(h, socket->getPollEvents(EpollScheduler::PollIn | EpollScheduler::PollRdHUp));
}

void SshConnectAwaiter::await_resume() {
    onResume();
    if (connectErrno != 0) {
        const auto rc = static_cast<ResultCode>(connectErrno);
        throw std::runtime_error("SSH connection failed: " + std::string(SshError::toString(rc)));
    }
}

SshFdWaitAwaiter::SshFdWaitAwaiter(std::shared_ptr<SshSocket> socket_,
                                   const CancellationTokenOpt &cancellationToken_,
                                   const uint32_t events_) :
    SshSocketAwaiterBase(std::move(socket_), cancellationToken_),
    events(events_) {
}

bool SshFdWaitAwaiter::await_ready() const noexcept {
    if (cancellationToken && cancellationToken->isStopped()) {
        return true;
    }
    return false;
}

void SshFdWaitAwaiter::await_suspend(const std::coroutine_handle<> h) {
    onSuspend(h, events);
}

void SshFdWaitAwaiter::await_resume() {
    onResume();
}
