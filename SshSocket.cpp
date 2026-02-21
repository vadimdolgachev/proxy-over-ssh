//
// Created by vadim on 28.01.2026.
//

#include "SshSocket.h"
#include "SSHProxy.h"

#include <libssh2.h>
#include <stdexcept>
#include <utility>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>  // for inet_pton, htons
#include <netinet/in.h>  // for sockaddr_in, sockaddr_in6

// libssh2 session block direction bits (from libssh2.h)
// libssh2_session_block_directions() returns these bits
#ifndef LIBSSH2_SESSION_BLOCK_INBOUND
#define LIBSSH2_SESSION_BLOCK_INBOUND  0x0001  // wants to read
#define LIBSSH2_SESSION_BLOCK_OUTBOUND 0x0002  // wants to write
#endif

namespace {
    std::string resultCodeToString(ResultCode rc) {
        switch (rc) {
            case ResultCode::Ok: return "Ok";
            case ResultCode::ErrAgain: return "ErrAgain";
            case ResultCode::ErrIO: return "ErrIO";
            case ResultCode::ErrTimeout: return "ErrTimeout";
            case ResultCode::ErrInvalidPrivateKey: return "ErrInvalidPrivateKey";
            case ResultCode::ErrUnknown: return "ErrUnknown";
            default: return "Unknown ResultCode";
        }
    }
}

// SshSocket implementation
SshSocket::SshSocket(SSHConfig sshConfig_)
    : sshConfig(std::move(sshConfig_)),
      tcpSocket(std::make_shared<Socket>()) {
    // Parse SSH server host as IP address to create proper IP endpoint
    // (not hostname endpoint, which can't be used for TCP connect)
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(sshConfig.port);

    if (inet_pton(AF_INET, sshConfig.host.c_str(), &addr.sin_addr) == 1) {
        // IPv4 address
        sshServerEndpoint = Endpoint(addr);
    } else {
        sockaddr_in6 addr6{};
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(sshConfig.port);
        if (inet_pton(AF_INET6, sshConfig.host.c_str(), &addr6.sin6_addr) == 1) {
            // IPv6 address
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
    std::cout << "SshSocket::tryTcpConnect: fd=" << (tcpSocket ? tcpSocket->fd() : -1) << "\n";
    if (!tcpSocket || tcpSocket->fd() < 0) {
        std::cout << "SshSocket::tryTcpConnect: invalid socket\n";
        return ResultCode::ErrIO;
    }

    int fd = tcpSocket->fd();
    auto [storage, len] = sshServerEndpoint.sockaddrStorage();

    std::cout << "SshSocket::tryTcpConnect: connecting to " << sshServerEndpoint.ipStr() << ":" << sshServerEndpoint.port() << "\n";
    const int rc = ::connect(fd, reinterpret_cast<const sockaddr *>(&storage), len);
    if (rc == 0) {
        state = State::TCP_CONNECTED;
        std::cout << "SshSocket::tryTcpConnect: connected immediately\n";
        return ResultCode::Ok;
    }

    const int err = errno;
    if (err == EINPROGRESS || err == EALREADY) {
        // Connection in progress, will be completed asynchronously
        std::cout << "SshSocket::tryTcpConnect: EINPROGRESS/EALREADY, will complete asynchronously\n";
        return ResultCode::ErrAgain;
    }

    if (err == EISCONN) {
        // Socket is already connected, check for any error
        int sockerr = 0;
        socklen_t sockerr_len = sizeof(sockerr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &sockerr_len) < 0) {
            std::cout << "SshSocket::tryTcpConnect: getsockopt failed, err=" << errno << "\n";
            return ResultCode::ErrIO;
        }
        if (sockerr != 0) {
            std::cout << "SshSocket::tryTcpConnect: socket error " << sockerr << " (" << strerror(sockerr) << ")\n";
            return ResultCode::ErrIO;
        }
        state = State::TCP_CONNECTED;
        std::cout << "SshSocket::tryTcpConnect: already connected successfully\n";
        return ResultCode::Ok;
    }

    // Other error
    std::cout << "SshSocket::tryTcpConnect: connect error " << err << " (" << strerror(err) << ")\n";
    return ResultCode::ErrIO;
}

ResultCode SshSocket::advanceConnection() {
    std::cout << "SshSocket::advanceConnection: current state=" << static_cast<int>(state) << "\n";
    switch (state) {
        case State::DISCONNECTED: {
            std::cout << "SshSocket::advanceConnection: DISCONNECTED -> tryTcpConnect\n";
            const auto rc = tryTcpConnect();
            if (rc == ResultCode::ErrAgain) {
                // TCP connection in progress, need to wait for EPOLLOUT
                pendingDirections = LIBSSH2_SESSION_BLOCK_OUTBOUND;
                std::cout << "SshSocket::advanceConnection: ErrAgain, pendingDirections=" << pendingDirections << "\n";
                return ResultCode::ErrAgain;
            }
            std::cout << "SshSocket::advanceConnection: tryTcpConnect result=" << resultCodeToString(rc) << "\n";
            return rc;
        }
        case State::TCP_CONNECTED: {
            std::cout << "SshSocket::advanceConnection: TCP_CONNECTED -> performHandshake\n";
            return performHandshake();
        }
        case State::SSH_HANDSHAKE: {
            std::cout << "SshSocket::advanceConnection: SSH_HANDSHAKE -> performAuthentication\n";
            return performAuthentication();
        }
        case State::SSH_AUTHENTICATED: {
            std::cout << "SshSocket::advanceConnection: SSH_AUTHENTICATED -> createChannel\n";
            return createChannel();
        }
        case State::CHANNEL_CREATED:
            std::cout << "SshSocket::advanceConnection: already CHANNEL_CREATED\n";
            return ResultCode::Ok;
        case State::ERROR:
            std::cout << "SshSocket::advanceConnection: ERROR state\n";
            return ResultCode::ErrUnknown;
    }
    std::cout << "SshSocket::advanceConnection: unknown state\n";
    return ResultCode::ErrUnknown;
}

ResultCode SshSocket::performHandshake() {
    if (!tcpSocket || tcpSocket->fd() < 0) {
        return ResultCode::ErrIO;
    }

    // Create libssh2 session if not exists
    if (!libssh2Session) {
        libssh2Session = libssh2_session_init();
        if (!libssh2Session) {
            state = State::ERROR;
            return ResultCode::ErrUnknown;
        }
        // Set NON-blocking mode for async operation
        libssh2_session_set_blocking(libssh2Session, 0);
    }

    // Perform handshake (non-blocking)
    const int rc = libssh2_session_handshake(libssh2Session, tcpSocket->fd());
    if (rc == LIBSSH2_ERROR_EAGAIN) {
        // Need to wait for I/O
        const int direction = libssh2_session_block_directions(libssh2Session);
        pendingDirections = direction;
        return ResultCode::ErrAgain;
    }

    if (rc != 0) {
        // Error
        libssh2_session_free(libssh2Session);
        libssh2Session = nullptr;
        state = State::ERROR;
        return ResultCode::ErrUnknown;
    }

    state = State::SSH_HANDSHAKE;
    pendingDirections = 0;
    return ResultCode::Ok;
}

ResultCode SshSocket::performAuthentication() {
    if (!libssh2Session) {
        return ResultCode::ErrUnknown;
    }

    int rc;
    if (sshConfig.privateKeyData.has_value()) {
        rc = libssh2_userauth_publickey_frommemory(libssh2Session,
                                                   sshConfig.username.c_str(),
                                                   sshConfig.username.length(),
                                                   nullptr,
                                                   0,
                                                   sshConfig.privateKeyData.value().c_str(),
                                                   sshConfig.privateKeyData.value().length(),
                                                   nullptr);
    } else if (sshConfig.privateKeyPath.has_value()) {
        rc = libssh2_userauth_publickey_fromfile_ex(libssh2Session,
                                                    sshConfig.username.c_str(),
                                                    static_cast<unsigned int>(sshConfig.username.length()),
                                                    nullptr,
                                                    sshConfig.privateKeyPath.value().c_str(),
                                                    nullptr);
    } else {
        return ResultCode::ErrInvalidPrivateKey;
    }

    if (rc == LIBSSH2_ERROR_EAGAIN) {
        // Need to wait for I/O
        const int direction = libssh2_session_block_directions(libssh2Session);
        pendingDirections = direction;
        return ResultCode::ErrAgain;
    }

    if (rc != 0) {
        // Authentication failed
        libssh2_session_free(libssh2Session);
        libssh2Session = nullptr;
        state = State::ERROR;
        return ResultCode::ErrUnknown;
    }

    state = State::SSH_AUTHENTICATED;
    pendingDirections = 0;
    return ResultCode::Ok;
}

ResultCode SshSocket::createChannel() {
    if (!libssh2Session) {
        return ResultCode::ErrUnknown;
    }

    // Convert targetEndpoint to host and port
    // Use host() instead of ipStr() to handle both IP and hostname endpoints
    std::string host = targetEndpoint.host();
    int port = targetEndpoint.port();

    std::cout << "Creating SSH channel to " << host << ":" << port << "\n";

    // Create direct-tcpip channel (non-blocking)
    libssh2Channel = libssh2_channel_direct_tcpip_ex(libssh2Session,
                                                     host.c_str(),
                                                     port,
                                                     "::1", // source host (not important)
                                                     0); // source port
    if (!libssh2Channel) {
        const int lastErr = libssh2_session_last_errno(libssh2Session);
        std::cout << "Failed to create SSH channel, error: " << lastErr << "\n";
        if (lastErr == LIBSSH2_ERROR_EAGAIN) {
            // Need to wait for I/O
            const int direction = libssh2_session_block_directions(libssh2Session);
            pendingDirections = direction;
            return ResultCode::ErrAgain;
        }

        // Failed to create channel
        libssh2_session_free(libssh2Session);
        libssh2Session = nullptr;
        state = State::ERROR;
        return ResultCode::ErrUnknown;
    }

    std::cout << "SSH channel created successfully\n";
    state = State::CHANNEL_CREATED;
    pendingDirections = 0;
    return ResultCode::Ok;
}

SshConnectAwaiter SshSocket::connect(const Endpoint &targetEndpoint_) {
    targetEndpoint = targetEndpoint_;
    return {shared_from_this(), targetEndpoint};
}

CoroTask<void> SshSocket::connectAsync(const Endpoint &targetEndpoint_) {
    targetEndpoint = targetEndpoint_;

    while (state != State::CHANNEL_CREATED) {
        const auto rc = advanceConnection();
        if (rc == ResultCode::ErrAgain) {
            // Wait for I/O using the existing awaiter
            SshConnectAwaiter awaiter{shared_from_this(), targetEndpoint};
            co_await awaiter;
            continue;
        }
        if (rc != ResultCode::Ok) {
            throw std::runtime_error("SSH connection failed: " + resultCodeToString(rc));
        }
        // State advanced, continue loop
    }
}

SshReadAwaiter SshSocket::read(std::span<unsigned char> buffer) {
    return {shared_from_this(), buffer};
}

SshWriteAwaiter SshSocket::write(std::span<unsigned char> buffer) {
    return {shared_from_this(), buffer};
}

int SshSocket::fd() const noexcept {
    if (tcpSocket) {
        return tcpSocket->fd();
    }
    return -1;
}

void SshSocket::close() noexcept {
    if (libssh2Channel) {
        libssh2_channel_free(libssh2Channel);
        libssh2Channel = nullptr;
    }
    if (libssh2Session) {
        libssh2_session_free(libssh2Session);
        libssh2Session = nullptr;
    }
    if (tcpSocket) {
        tcpSocket->close();
    }
    state = State::DISCONNECTED;
}

// SshConnectAwaiter implementation
SshConnectAwaiter::SshConnectAwaiter(std::shared_ptr<SshSocket> sshSocket_, Endpoint targetEndpoint_)
    : sshSocket(std::move(sshSocket_)),
      targetEndpoint(std::move(targetEndpoint_)) {
}

bool SshConnectAwaiter::await_ready() const noexcept {
    // If already fully connected, return true
    if (sshSocket->state == SshSocket::State::CHANNEL_CREATED) {
        return true;
    }

    // Try to advance connection as far as possible without blocking
    while (true) {
        const auto rc = sshSocket->advanceConnection();

        if (rc == ResultCode::ErrAgain) {
            // Need to wait for I/O
            return false;
        }

        if (rc != ResultCode::Ok) {
            // Error occurred
            connectErrno = static_cast<int>(rc);
            return true; // Will throw in await_resume
        }

        // rc == ResultCode::Ok
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

    // Determine which events to wait for based on pendingDirections
    uint32_t events = 0;
    if (sshSocket->pendingDirections & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
        events |= EpollScheduler::PollEvents::EPOLLOUT;
    }
    if (sshSocket->pendingDirections & LIBSSH2_SESSION_BLOCK_INBOUND) {
        events |= EpollScheduler::PollEvents::EPOLLIN;
    }

    // If no pending directions (e.g., initial TCP connect), wait for EPOLLOUT
    if (events == 0) {
        events = EpollScheduler::PollEvents::EPOLLOUT | EPOLLERR;
    }

    this->getScheduler()->add(events, sshSocket->fd(), h);
}

void SshConnectAwaiter::await_resume() {
    if (connectErrno != 0) {
        const ResultCode rc = static_cast<ResultCode>(connectErrno);
        throw std::runtime_error("SSH connection failed: " + resultCodeToString(rc));
    }

    // Continue advancing the connection state
    // After epoll reported readiness, we should be able to make progress
    while (sshSocket->state != SshSocket::State::CHANNEL_CREATED) {
        const auto rc = sshSocket->advanceConnection();

        if (rc == ResultCode::ErrAgain) {
            // This shouldn't happen after epoll reported readiness
            throw std::runtime_error("SSH connection state machine error: unexpected ErrAgain");
        }

        if (rc != ResultCode::Ok) {
            throw std::runtime_error("SSH connection failed: " + resultCodeToString(rc));
        }

        // rc == ResultCode::Ok
        if (sshSocket->state == SshSocket::State::CHANNEL_CREATED) {
            return; // Connection complete
        }

        // State advanced but not yet fully connected, continue loop
    }
}

// SshReadAwaiter implementation
SshReadAwaiter::SshReadAwaiter(std::shared_ptr<SshSocket> sshSocket_, std::span<unsigned char> buffer_)
    : sshSocket(std::move(sshSocket_)), buffer(buffer_) {
}

bool SshReadAwaiter::await_ready() const noexcept {
    if (!sshSocket->libssh2Session) {
        peekErrno = EINVAL;
        return true;
    }

    // Try non-blocking read
    const ssize_t n = libssh2_channel_read(sshSocket->libssh2Channel,
                                           reinterpret_cast<char*>(buffer.data()),
                                           buffer.size());
    if (n > 0) {
        // Data available immediately
        peekResult = static_cast<size_t>(n);
        return true;
    }

    if (n == 0) {
        // EOF - channel closed
        peekEof = true;
        return true;
    }

    // n < 0: error or EAGAIN
    if (n == LIBSSH2_ERROR_EAGAIN) {
        return false; // Need to wait for I/O
    }

    peekErrno = static_cast<int>(-n);
    return true;
}

void SshReadAwaiter::await_suspend(std::coroutine_handle<> h) {
    if (this->getScheduler() == nullptr) {
        throw std::runtime_error("No scheduler set for SshReadAwaiter");
    }

    // Determine which events to wait for
    uint32_t events = 0;
    if (sshSocket->libssh2Session) {
        const int directions = libssh2_session_block_directions(sshSocket->libssh2Session);
        if (directions & LIBSSH2_SESSION_BLOCK_INBOUND) {
            events |= EpollScheduler::PollEvents::EPOLLIN;
        }
        if (directions & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
            events |= EpollScheduler::PollEvents::EPOLLOUT;
        }
    }

    // Default to EPOLLIN if no directions
    if (events == 0) {
        events = EpollScheduler::PollEvents::EPOLLIN;
    }

    this->getScheduler()->add(events, sshSocket->fd(), h);
}

size_t SshReadAwaiter::await_resume() {
    if (peekErrno != 0) {
        throw std::system_error(peekErrno, std::system_category(), "SSH read failed");
    }
    if (peekEof) {
        return 0; // EOF
    }
    if (peekResult.has_value()) {
        return *peekResult;
    }

    // Perform the actual read after resuming
    if (!sshSocket->libssh2Channel) {
        throw std::runtime_error("SSH channel not created");
    }

    while (true) {
        const ssize_t n = libssh2_channel_read(sshSocket->libssh2Channel,
                                               reinterpret_cast<char*>(buffer.data()),
                                               buffer.size());
        if (n >= 0) {
            return static_cast<size_t>(n);
        }

        if (n == LIBSSH2_ERROR_EAGAIN) {
            // This shouldn't happen after epoll reported readiness
            // Try again briefly
            continue;
        }

        throw std::runtime_error("SSH channel read error: " + std::to_string(n));
    }
}

// SshWriteAwaiter implementation
SshWriteAwaiter::SshWriteAwaiter(std::shared_ptr<SshSocket> sshSocket_, std::span<unsigned char> buffer_)
    : sshSocket(std::move(sshSocket_)), buffer(buffer_) {
}

bool SshWriteAwaiter::await_ready() const noexcept {
    if (!sshSocket->libssh2Session) {
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

    // n < 0: error or EAGAIN
    if (n == LIBSSH2_ERROR_EAGAIN) {
        return false; // Need to wait for I/O
    }

    pollErrno = static_cast<int>(-n);
    pollError = true;
    return true;
}

void SshWriteAwaiter::await_suspend(std::coroutine_handle<> h) {
    if (this->getScheduler() == nullptr) {
        throw std::runtime_error("No scheduler set for SshWriteAwaiter");
    }

    // Determine which events to wait for
    uint32_t events = 0;
    if (sshSocket->libssh2Session) {
        const int directions = libssh2_session_block_directions(sshSocket->libssh2Session);
        if (directions & LIBSSH2_SESSION_BLOCK_INBOUND) {
            events |= EpollScheduler::PollEvents::EPOLLIN;
        }
        if (directions & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
            events |= EpollScheduler::PollEvents::EPOLLOUT;
        }
    }

    // Default to EPOLLOUT if no directions
    if (events == 0) {
        events = EpollScheduler::PollEvents::EPOLLOUT;
    }

    this->getScheduler()->add(events, sshSocket->fd(), h);
}

size_t SshWriteAwaiter::await_resume() {
    if (pollError) {
        throw std::system_error(pollErrno, std::system_category(), "SSH write failed");
    }
    if (pollResult.has_value()) {
        return *pollResult;
    }

    // Perform the actual write after resuming
    if (!sshSocket->libssh2Channel) {
        throw std::runtime_error("SSH channel not created");
    }

    while (true) {
        const ssize_t n = libssh2_channel_write(sshSocket->libssh2Channel,
                                                reinterpret_cast<const char*>(buffer.data()),
                                                buffer.size());
        if (n >= 0) {
            return static_cast<size_t>(n);
        }

        if (n == LIBSSH2_ERROR_EAGAIN) {
            // This shouldn't happen after epoll reported readiness
            // Try again briefly
            continue;
        }

        throw std::runtime_error("SSH channel write error: " + std::to_string(n));
    }
}
