//
// Created by vadim on 28.01.2026.
//

#include <cassert>
#include <cerrno>
#include <span>
#include <system_error>
#include <utility>

#include <poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "Socket.h"
#include "Logger.h"

Socket::Socket() :
    fd_(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) {
}

Socket::Socket(const int fd) :
    fd_(fd) {
}

Socket::~Socket() {
    close();
}

void Socket::setReusePort(const bool reusePort) {
    const int reuse = reusePort ? 1 : 0;
    if (setsockopt(fd_.get(), SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        throw std::system_error(errno, std::system_category(), "socket port reuse failed");
    }
}

void Socket::setReuseAddr(const bool reuseAddr) {
    const int reuse = reuseAddr ? 1 : 0;
    if (setsockopt(fd_.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        throw std::system_error(errno, std::system_category(), "SO_REUSEADDR failed");
    }
}

void Socket::close() noexcept {
    fd_.reset(-1);
}

ConnectSocketAwaiter Socket::connect(Endpoint endpoint, CancellationTokenOpt ct) {
    return {shared_from_this(), std::move(endpoint), std::move(ct)};
}

int Socket::fd() const noexcept {
    return fd_.get();
}

bool Socket::bind(const Endpoint &endpoint) const noexcept {
    try {
        auto [storage, len] = endpoint.sockaddrStorage();
        return ::bind(fd_.get(), reinterpret_cast<const sockaddr *>(&storage), len) == 0;
    } catch (const std::exception &) {
        return false;
    }
}

ListenSocketAwaiter Socket::listen(CancellationToken ct) const {
    ::listen(fd_.get(), SOMAXCONN);
    return {fd_.get(), std::move(ct)};
}

bool Socket::isEof() const noexcept {
    if (fd() < 0) {
        return true;
    }
    unsigned char tmp;
    const ssize_t result = recv(fd(), &tmp, 1, MSG_PEEK | MSG_DONTWAIT);
    if (result == 0) {
        return true;
    }
    if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return false;
        }
        return true;
    }
    return false;
}

ListenSocketAwaiter::ListenSocketAwaiter(const int fd_, CancellationToken ct_) :
    fd(fd_),
    ct(std::move(ct_)) {
    if (fd_ == -1) {
        throw std::runtime_error("Invalid socket descriptor");
    }
}

bool ListenSocketAwaiter::await_ready() const noexcept {
    return false;
}

void ListenSocketAwaiter::await_suspend(const std::coroutine_handle<> h) {
    assert(this->getScheduler() != nullptr);
    this->getScheduler()->add(EpollScheduler::PollIn, ct.getFd(), h);
    this->getScheduler()->add(EpollScheduler::PollIn, fd, h);
}

AcceptedSocket ListenSocketAwaiter::await_resume() {
    this->getScheduler()->remove(ct.getFd(), handle);
    sockaddr_storage addr{};
    socklen_t socklen = sizeof(addr);
    const int socketFd = accept4(fd, reinterpret_cast<sockaddr *>(&addr), &socklen, SOCK_NONBLOCK);
    if (socketFd == -1) {
        if (errno == EAGAIN || errno == EINTR) {
            if (ct.isStopped()) {
                throw CancellationTokenException{};
            }
        }
        throw std::system_error(errno,
            std::system_category(),
            "accept4 failed");
    }

    if (addr.ss_family == AF_INET6) {
        sockaddr_in6 addr6{};
        std::memcpy(&addr6, &addr, sizeof(sockaddr_in6));
        return {std::make_shared<Socket>(socketFd), Endpoint(addr6)};
    }

    // Default to IPv4 (for AF_INET or unknown)
    sockaddr_in addr4{};
    std::memcpy(&addr4, &addr, sizeof(sockaddr_in));
    return {std::make_shared<Socket>(socketFd), Endpoint(addr4)};
}

ReadSocketAwaiter Socket::read(std::span<unsigned char> buffer, CancellationTokenOpt ct) {
    if (buffer.empty()) {
        throw std::runtime_error("Buffer is empty");
    }
    return {shared_from_this(), buffer, std::move(ct)};
}

WriteSocketAwaiter Socket::write(std::span<unsigned char> buffer, CancellationTokenOpt ct) {
    return {shared_from_this(), buffer, std::move(ct)};
}

ReadSocketAwaiter::ReadSocketAwaiter(SocketPtr socket_, const std::span<unsigned char> buffer_, CancellationTokenOpt ct_) :
    socket(std::move(socket_)),
    buffer(buffer_),
    ct(std::move(ct_)) {
    if (!socket || socket->fd() == -1) {
        throw std::runtime_error("Invalid socket descriptor");
    }
    if (buffer_.empty()) {
        throw std::runtime_error("Buffer is empty");
    }
}

bool ReadSocketAwaiter::await_ready() const noexcept {
    // Check if data is available immediately without blocking
    while (true) {
        unsigned char tmp;
        const ssize_t result = recv(socket->fd(), &tmp, 1, MSG_PEEK | MSG_DONTWAIT);
        if (result > 0) {
            return true;
        }
        if (result == 0) {
            peekEof = true;
            return true;
        }
        const int err = errno;
        if (err == EINTR) {
            continue;
        }
        if (err == EAGAIN) {
            return false;
        }
        peekErrno = err;
        return true;
    }
}

void ReadSocketAwaiter::await_suspend(const std::coroutine_handle<> h) {
    handle = h;
    assert(this->getScheduler() != nullptr);
    if (ct) {
        this->getScheduler()->add(EpollScheduler::PollIn, ct.value().getFd(), h);
    }
    this->getScheduler()->add(EpollScheduler::PollIn, socket->fd(), h);
}

size_t ReadSocketAwaiter::await_resume() {
    if (ct && handle) {
        this->getScheduler()->remove(ct.value().getFd(), handle);
    }
    if (peekErrno != 0) {
        throw std::system_error(peekErrno, std::system_category(), "recv failed");
    }
    if (peekEof) {
        return 0;
    }

    while (true) {
        if (ct && ct.value().isStopped()) {
            throw CancellationTokenException{};
        }
        const ssize_t bytesRead = recv(socket->fd(), buffer.data(), buffer.size(), 0);
        if (bytesRead < 0) {
            log_d("ReadSocketAwaiter::await_resume bytesRead={}, errno={}\n", bytesRead, errno);
            if (errno == EAGAIN || errno == EINTR) {

            }
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::system_category(), "recv failed");
        }
        return static_cast<size_t>(bytesRead);
    }
}

WriteSocketAwaiter::WriteSocketAwaiter(SocketPtr socket_, const std::span<unsigned char> buffer_, CancellationTokenOpt ct_) :
    socket(std::move(socket_)),
    buffer(buffer_),
    ct(std::move(ct_)) {
}

bool WriteSocketAwaiter::await_ready() const noexcept {
    while (true) {
        pollfd pfd{};
        pfd.fd = socket->fd();
        pfd.events = POLLOUT;
        const int result = poll(&pfd, 1, 0);
        if (result < 0) {
            const int err = errno;
            if (err == EINTR) {
                continue;
            }
            pollErrno = err;
            pollError = true;
            return true;
        }
        if (result > 0) {
            pollRevents = pfd.revents;
            if (pfd.revents & POLLOUT) {
                return true;
            }
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                return true;
            }
        }
        return false;
    }
}

void WriteSocketAwaiter::await_suspend(const std::coroutine_handle<> h) {
    handle = h;
    assert(this->getScheduler() != nullptr);
    if (ct) {
        this->getScheduler()->add(EpollScheduler::PollIn, ct.value().getFd(), h);
    }
    this->getScheduler()->add(EpollScheduler::PollOut, socket->fd(), h);
}

size_t WriteSocketAwaiter::await_resume() {
    if (ct && handle) {
        this->getScheduler()->remove(ct.value().getFd(), handle);
    }
    if (pollError) {
        throw std::system_error(pollErrno, std::system_category(), "poll failed");
    }

    if (pollRevents & (POLLERR | POLLHUP | POLLNVAL)) {
        int sockerr = 0;
        socklen_t sockerr_len = sizeof(sockerr);
        if (getsockopt(socket->fd(), SOL_SOCKET, SO_ERROR, &sockerr, &sockerr_len) < 0) {
            throw std::system_error(errno, std::system_category(), "getsockopt failed");
        }
        if (sockerr != 0) {
            throw std::system_error(sockerr, std::system_category(), "socket error");
        }
    }

    size_t totalSent = 0;
    while (totalSent < buffer.size()) {
        const ssize_t sent =
                send(socket->fd(), buffer.data() + totalSent, buffer.size() - totalSent, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                if (ct && ct.value().isStopped()) {
                    throw CancellationTokenException{};
                }
            }
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::system_category(), "send failed");
        }
        if (sent == 0) {
            break;
        }
        totalSent += static_cast<size_t>(sent);
    }
    return totalSent;
}

ConnectSocketAwaiter::ConnectSocketAwaiter(SocketPtr socket_,
                                           Endpoint endpoint_,
                                           CancellationTokenOpt ct_) :
    socket(std::move(socket_)),
    endpoint(std::move(endpoint_)),
    ct(std::move(ct_)) {
    if (!socket || socket->fd() == -1) {
        throw std::runtime_error("Invalid socket descriptor");
    }
}

bool ConnectSocketAwaiter::await_ready() const noexcept {
    try {
        auto [storage, len] = endpoint.sockaddrStorage();

        while (true) {
            if (const int result = connect(socket->fd(), reinterpret_cast<const sockaddr *>(&storage), len);
                result == 0) {
                return true;
            }

            const int err = errno;
            if (err == EINTR) {
                if (ct && ct.value().isStopped()) {
                    throw CancellationTokenException{};
                }
                continue;
            }

            if (err == EINPROGRESS || err == EALREADY) {
                connectPending = true;
                return false;
            }

            if (err == EISCONN) {
                return true;
            }

            connectErrno = err;
            return true;
        }
    } catch (const std::exception &) {
        connectErrno = EINVAL;
        return true;
    }
}

void ConnectSocketAwaiter::await_suspend(const std::coroutine_handle<> h) {
    handle = h;
    assert(this->getScheduler() != nullptr);
    if (ct) {
        this->getScheduler()->add(EpollScheduler::PollIn, ct.value().getFd(), h);
    }
    this->getScheduler()->add(EpollScheduler::PollOut | EpollScheduler::PollErr, socket->fd(), h);
}

void ConnectSocketAwaiter::await_resume() {
    if (ct && handle) {
        this->getScheduler()->remove(ct.value().getFd(), handle);
    }
    if (connectErrno != 0) {
        throw std::system_error(connectErrno, std::system_category(), "connect failed");
    }

    if (connectPending) {
        if (ct && ct.value().isStopped()) {
            throw CancellationTokenException{};
        }
        int sockerr = 0;
        socklen_t sockerr_len = sizeof(sockerr);
        if (getsockopt(socket->fd(), SOL_SOCKET, SO_ERROR, &sockerr, &sockerr_len) < 0) {
            throw std::system_error(errno, std::system_category(), "getsockopt failed");
        }
        if (sockerr != 0) {
            throw std::system_error(sockerr, std::system_category(), "connect failed");
        }
    }
}
