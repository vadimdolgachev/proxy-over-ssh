//
// Created by vadim on 28.01.2026.
//

#ifndef PROXY_OVER_SSH_SOCKET_H
#define PROXY_OVER_SSH_SOCKET_H

#include "CoroTask.h"
#include "Endpoint.h"

#include <span>
#include <memory>

struct AcceptedSocket;

struct ListenSocketAwaiter final : SchedulerAware<EpollScheduler> {
    explicit ListenSocketAwaiter(int fd_);

    [[nodiscard]] bool await_ready() const noexcept;

    void await_suspend(std::coroutine_handle<> h);

    AcceptedSocket await_resume();

private:
    int fd;
};

class Socket;
using SocketPtr = std::shared_ptr<Socket>;

struct ReadSocketAwaiter final : SchedulerAware<EpollScheduler> {
    ReadSocketAwaiter(SocketPtr socket_, std::span<unsigned char> buffer_);

    [[nodiscard]] bool await_ready() const noexcept;

    void await_suspend(std::coroutine_handle<> h);

    size_t await_resume();

private:
    SocketPtr socket;
    std::span<unsigned char> buffer;
    mutable int peekErrno = 0;
    mutable bool peekEof = false;
};

struct WriteSocketAwaiter final : SchedulerAware<EpollScheduler> {
    WriteSocketAwaiter(SocketPtr socket_, std::span<unsigned char> buffer_);

    [[nodiscard]] bool await_ready() const noexcept;

    void await_suspend(std::coroutine_handle<> h);

    size_t await_resume();

private:
    SocketPtr socket;
    std::span<unsigned char> buffer;
    mutable int pollErrno = 0;
    mutable bool pollError = false;
    mutable short pollRevents = 0;
};

struct ConnectSocketAwaiter final : SchedulerAware<EpollScheduler> {
    ConnectSocketAwaiter(SocketPtr socket_, Endpoint endpoint_);

    [[nodiscard]] bool await_ready() const noexcept;

    void await_suspend(std::coroutine_handle<> h);

    void await_resume();

private:
    SocketPtr socket;
    Endpoint endpoint;
    mutable int connectErrno = 0;
    mutable bool connectPending = false;
};

class Socket final : public std::enable_shared_from_this<Socket> {
public:
    Socket();

    explicit Socket(int fd);

    Socket(const Socket &) = delete;

    Socket &operator=(const Socket &) = delete;

    Socket(Socket &&) = default;

    Socket &operator=(Socket &&) = default;

    ~Socket();

    void setReusePort(bool reusePort);

    void close() noexcept;

    [[nodiscard]] int fd() const noexcept;

    [[nodiscard]] bool bind(const Endpoint &endpoint) const noexcept;

    [[nodiscard]] ConnectSocketAwaiter connect(Endpoint endpoint);

    [[nodiscard]] ListenSocketAwaiter listen() const;

    [[nodiscard]] ReadSocketAwaiter read(std::span<unsigned char> buffer);

    [[nodiscard]] WriteSocketAwaiter write(std::span<unsigned char> buffer);

private:
    UniqueFd fd_;
};

struct AcceptedSocket final {
    SocketPtr socket;
    Endpoint endpoint;
};

#endif //PROXY_OVER_SSH_SOCKET_H
