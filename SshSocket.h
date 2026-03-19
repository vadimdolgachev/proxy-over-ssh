//
// Created by vadim on 28.01.2026.
//

#ifndef PROXY_OVER_SSH_SSHSOCKET_H
#define PROXY_OVER_SSH_SSHSOCKET_H

#include "CoroTask.h"
#include "Endpoint.h"
#include "Socket.h"

#include <span>
#include <memory>
#include <optional>

#include "SSHProxy.h"

class SshSocket;

// libssh2 forward declarations
typedef struct _LIBSSH2_SESSION LIBSSH2_SESSION;
typedef struct _LIBSSH2_CHANNEL LIBSSH2_CHANNEL;

struct SshConnectAwaiter final : SchedulerAware<EpollScheduler> {
    SshConnectAwaiter(std::shared_ptr<SshSocket> sshSocket_, Endpoint targetEndpoint_);

    [[nodiscard]] bool await_ready() const noexcept;

    void await_suspend(std::coroutine_handle<> h);

    void await_resume();

private:
    std::shared_ptr<SshSocket> sshSocket;
    Endpoint targetEndpoint;
    mutable int connectErrno = 0;
};

struct SshReadAwaiter final : SchedulerAware<EpollScheduler> {
    SshReadAwaiter(std::shared_ptr<SshSocket> sshSocket_, std::span<unsigned char> buffer_);

    [[nodiscard]] bool await_ready() const noexcept;

    void await_suspend(std::coroutine_handle<> h);

    size_t await_resume();

private:
    std::shared_ptr<SshSocket> sshSocket;
    std::span<unsigned char> buffer;
    mutable int peekErrno = 0;
    mutable bool peekEof = false;
    mutable std::optional<size_t> peekResult;
    std::chrono::steady_clock::time_point startTime;
    static constexpr std::chrono::seconds timeout{30};
};

struct SshWriteAwaiter final : SchedulerAware<EpollScheduler> {
    SshWriteAwaiter(std::shared_ptr<SshSocket> sshSocket_, std::span<unsigned char> buffer_);

    [[nodiscard]] bool await_ready() const noexcept;

    void await_suspend(std::coroutine_handle<> h);

    size_t await_resume();

private:
    std::shared_ptr<SshSocket> sshSocket;
    std::span<unsigned char> buffer;
    mutable int pollErrno = 0;
    mutable bool pollError = false;
    mutable short pollRevents = 0;
    mutable std::optional<size_t> pollResult;
};

class SshSocket : public std::enable_shared_from_this<SshSocket> {
public:
    explicit SshSocket(SSHConfig sshConfig_);

    SshSocket(const SshSocket &) = delete;

    SshSocket &operator=(const SshSocket &) = delete;

    ~SshSocket();

    [[nodiscard]] SshConnectAwaiter connect(const Endpoint &targetEndpoint_);

    [[nodiscard]] CoroTask<ResultCode> connectAsync(const Endpoint &targetEndpoint_);

    [[nodiscard]] SshReadAwaiter read(std::span<unsigned char> buffer);

    [[nodiscard]] SshWriteAwaiter write(std::span<unsigned char> buffer);

    [[nodiscard]] int fd() const noexcept;

    [[nodiscard]] bool isEof() const noexcept;

    void close() noexcept;

private:
    friend struct SshConnectAwaiter;
    friend struct SshReadAwaiter;
    friend struct SshWriteAwaiter;

    enum class State {
        DISCONNECTED,
        TCP_CONNECTED,
        SSH_HANDSHAKE,
        SSH_AUTHENTICATED,
        CHANNEL_CREATED,
        ERROR
    };

    SSHConfig sshConfig;
    Endpoint sshServerEndpoint;
    SocketPtr tcpSocket;
    LIBSSH2_SESSION *libssh2Session = nullptr;
    LIBSSH2_CHANNEL *libssh2Channel = nullptr;
    int pendingDirections = 0;
    uint32_t pendingEvents = 0;
    State state = State::DISCONNECTED;
    Endpoint targetEndpoint;

    ResultCode tryTcpConnect();

    ResultCode advanceConnection();

    ResultCode performHandshake();

    ResultCode performAuthentication();

    ResultCode createChannel();
};

using SshSocketPtr = std::shared_ptr<SshSocket>;

#endif //PROXY_OVER_SSH_SSHSOCKET_H
