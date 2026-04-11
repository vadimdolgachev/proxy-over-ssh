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
#include "SshError.h"
#include "Types.h"
#include "SessionPool.h"


ResultCode SshSocket::handleLibSsh2Result(int rc, const char *operation, const SshConStateMachine::State successState) {
    if (rc == LIBSSH2_ERROR_EAGAIN) {
        if (sessionHandle && sessionHandle->sshSession) {
            pendingDirections = sessionHandle->sshSession->blockDirections();
        } else {
            pendingDirections = LIBSSH2_SESSION_BLOCK_OUTBOUND; // fallback for TCP connect
        }
        return ResultCode::ErrAgain;
    }
    if (rc != 0) {
        sessionHandle = std::nullopt;
        SshError::logError(operation, rc);
        stateMachine.setState(State::ERROR);
        return SshError::libSsh2ToResultCode(rc);
    }
    stateMachine.setState(successState);
    pendingDirections = 0;
    return ResultCode::Ok;
}

ResultCode SshSocket::handleLibSsh2ChannelResult(const LIBSSH2_CHANNEL *const channel, const char *operation,
                                                 const std::string &host) {
    if (channel == nullptr) {
        const int lastErr = libssh2_session_last_errno(sessionHandle->sshSession->raw());
        if (lastErr == LIBSSH2_ERROR_EAGAIN) {
            pendingDirections = sessionHandle->sshSession->blockDirections();
            return ResultCode::ErrAgain;
        }
        sessionHandle = std::nullopt;
        SshError::logError(operation, lastErr, host);
        stateMachine.setState(State::ERROR);
        return SshError::libSsh2ToResultCode(lastErr);
    }
    stateMachine.setState(State::CHANNEL_CREATED);
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
        events |= EpollScheduler::PollEvents::EPOLLIN;
    }
    if (directions & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
        events |= EpollScheduler::PollEvents::EPOLLOUT;
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
                stateMachine.setState(State::SSH_AUTHENTICATED);
            } else {
                sessionHandle = std::nullopt;
            }
        }
    }

    while (stateMachine.getState() != State::CHANNEL_CREATED) {
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
    if (sessionHandle == std::nullopt) {
        sessionHandle = SshSessionHandler{
            .sshSession = nullptr,
            .tcpSocket = std::make_unique<Socket>(),
            .lastUsed = std::chrono::steady_clock::now(),
            .lastHealthCheck = std::chrono::steady_clock::now(),
            .failedHealthChecks = 0,
            .keepaliveConfigured = true,
        };
    }

    if (sessionHandle->tcpSocket == nullptr || sessionHandle->tcpSocket->fd() < 0) {
        return ResultCode::ErrIO;
    }

    const int fd = sessionHandle->tcpSocket->fd();
    auto [storage, len] = sshServerEndpoint.sockaddrStorage();

    if (const int rc = ::connect(fd, reinterpret_cast<const sockaddr *>(&storage), len);
        rc == 0) {
        stateMachine.setState(State::TCP_CONNECTED);
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
        stateMachine.setState(State::TCP_CONNECTED);
        return ResultCode::Ok;
    }

    return ResultCode::ErrIO;
}

ResultCode SshSocket::advanceConnection() {
    return stateMachine.advance(*this, &pendingDirections);
}

ResultCode SshSocket::performHandshake() {
    if (sessionHandle->sshSession == nullptr) {
        try {
            sessionHandle->sshSession = std::make_unique<SshSession>();
        } catch (const std::exception &e) {
            stateMachine.setState(State::ERROR);
            return ResultCode::ErrUnknown;
        }
    }

    const int rc = sessionHandle->sshSession->handshake(sessionHandle->tcpSocket);
    return handleLibSsh2Result(rc, "performHandshake", State::SSH_HANDSHAKE);
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

    return handleLibSsh2Result(rc, "performAuthentication", State::SSH_AUTHENTICATED);
}

ResultCode SshSocket::createChannel() {
    if (sessionHandle->sshSession == nullptr) {
        return ResultCode::ErrUnknown;
    }

    const auto host = targetEndpoint.host();
    const int port = targetEndpoint.port();

    LIBSSH2_CHANNEL *channel = libssh2_channel_direct_tcpip_ex(sessionHandle->sshSession->raw(),
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

SshConnectAwaiter SshSocket::connect(const Endpoint &targetEndpoint_) {
    targetEndpoint = targetEndpoint_;
    return {shared_from_this(), targetEndpoint};
}

CoroTask<ResultCode> SshSocket::connectAsync(const Endpoint &targetEndpoint_) {
    targetEndpoint = targetEndpoint_;

    while (true) {
        const auto rc = tryConnectNonBlocking();
        if (rc == ResultCode::Ok) {
            co_return ResultCode::Ok;
        }
        if (rc != ResultCode::ErrAgain) {
            co_return rc;
        }
        co_await SshConnectAwaiter{shared_from_this(), targetEndpoint};
    }
}

CoroTask<size_t> SshSocket::readAsync(std::span<uint8_t> buffer) {
    while (true) {
        if (libSsh2Channel == nullptr) {
            co_return 0;
        }

        const ssize_t n = libssh2_channel_read(libSsh2Channel,
                                               reinterpret_cast<char *>(buffer.data()),
                                               buffer.size());
        if (n > 0) {
            co_return static_cast<size_t>(n);
        }

        if (libssh2_channel_eof(libSsh2Channel)) {
            co_return 0;
        }

        if (n == LIBSSH2_ERROR_EAGAIN) {
            co_await SshFdWaitAwaiter{shared_from_this()};
            continue;
        }

        if (n == 0) {
            co_await SshFdWaitAwaiter{shared_from_this()};
            continue;
        }

        if (n == LIBSSH2_ERROR_CHANNEL_CLOSED) {
            co_return 0;
        }

        throw std::runtime_error("SSH channel read error: " + std::to_string(n));
    }
}

CoroTask<size_t> SshSocket::writeAsync(const std::span<const uint8_t> data) {
    while (true) {
        if (libSsh2Channel == nullptr) {
            co_return 0;
        }

        const ssize_t n = libssh2_channel_write(libSsh2Channel,
                                                reinterpret_cast<const char *>(data.data()),
                                                data.size());
        if (n > 0) {
            co_return static_cast<size_t>(n);
        }

        if (n == LIBSSH2_ERROR_EAGAIN) {
            if (libssh2_channel_eof(libSsh2Channel)) {
                co_return 0;
            }
            co_await SshFdWaitAwaiter{shared_from_this()};
            continue;
        }

        if (n == LIBSSH2_ERROR_CHANNEL_CLOSED) {
            co_return 0;
        }

        if (n < 0) {
            throw std::runtime_error("SSH channel write error: " + std::to_string(n));
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
        libssh2_channel_close(libSsh2Channel);
        libssh2_channel_free(libSsh2Channel);
        libSsh2Channel = nullptr;
    }

    if (sessionHandle == std::nullopt) {
        return;
    }

    if (sessionPool != nullptr && stateMachine.getState() != State::ERROR) {
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
    stateMachine.setState(State::DISCONNECTED);
    pendingDirections = 0;
}

SshConnectAwaiter::SshConnectAwaiter(std::shared_ptr<SshSocket> sshSocket_, Endpoint targetEndpoint_)
    : SshSocketAwaiterBase(std::move(sshSocket_)),
      targetEndpoint(std::move(targetEndpoint_)) {
}

bool SshConnectAwaiter::await_ready() const noexcept {
    if (sshSocket->stateMachine.getState() == SshConStateMachine::State::CHANNEL_CREATED) {
        return true;
    }

    if (sshSocket->pendingDirections != 0) {
        return false;
    }

    const auto rc = sshSocket->tryConnectNonBlocking();
    if (rc == ResultCode::ErrAgain) {
        return false;
    }
    if (rc != ResultCode::Ok) {
        connectErrno = static_cast<int>(rc);
        return true;
    }
    return true;
}

void SshConnectAwaiter::await_suspend(std::coroutine_handle<> h) {
    assert(this->getScheduler() != nullptr);
    uint32_t events = computePollEvents(EpollScheduler::PollEvents::EPOLLIN);
    events |= EpollScheduler::PollEvents::EPOLLERR | EpollScheduler::PollEvents::EPOLLHUP | EPOLLRDHUP;
    this->getScheduler()->add(events, sshSocket->fd(), h);
}

void SshConnectAwaiter::await_resume() {
    if (connectErrno != 0) {
        const auto rc = static_cast<ResultCode>(connectErrno);
        throw std::runtime_error("SSH connection failed: " + std::string(SshError::toString(rc)));
    }
}

bool SshFdWaitAwaiter::await_ready() const noexcept {
    return false;
}

void SshFdWaitAwaiter::await_suspend(const std::coroutine_handle<> h) {
    scheduleResume(h, EpollScheduler::PollEvents::EPOLLIN | EpollScheduler::PollEvents::EPOLLOUT);
}

void SshFdWaitAwaiter::await_resume() noexcept {
}
