//
// Created by vadim on 28.01.2026.
//

#ifndef PROXY_OVER_SSH_SSHSOCKET_H
#define PROXY_OVER_SSH_SSHSOCKET_H

#include <span>
#include <memory>
#include <optional>

#include "libssh2.h"

#include "BackendSocket.h"
#include "CoroTask.h"
#include "Endpoint.h"
#include "SSHProxy.h"
#include "SessionPool.h"
#include "SshSessionHandler.h"

class SshSocket;

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

class SshSocket : public IBackendSocket, public std::enable_shared_from_this<SshSocket> {
public:
    SshSocket(SSHConfig sshConfig_, const std::shared_ptr<SessionPool> &sessionPool_);

    SshSocket(const SshSocket &) = delete;

    SshSocket &operator=(const SshSocket &) = delete;

    ~SshSocket() override;

    [[nodiscard]] SshConnectAwaiter connect(const Endpoint &targetEndpoint_);

    [[nodiscard]] CoroTask<ResultCode> connectAsync(const Endpoint &targetEndpoint_) override;

    [[nodiscard]] SshReadAwaiter read(std::span<unsigned char> buffer);

    [[nodiscard]] SshWriteAwaiter write(std::span<unsigned char> buffer);

    [[nodiscard]] CoroTask<size_t> readAsync(std::span<uint8_t> buffer) override;

    [[nodiscard]] CoroTask<size_t> writeAsync(std::span<const uint8_t> data) override;

    [[nodiscard]] int fd() const noexcept override;

    [[nodiscard]] bool isEof() const noexcept override;

    void close() noexcept override;

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

    ResultCode tryTcpConnect();

    ResultCode advanceConnection();

    ResultCode performHandshake();

    ResultCode performAuthentication();

    ResultCode createChannel();

    std::shared_ptr<SessionPool> sessionPool;
    SSHConfig sshConfig;
    Endpoint sshServerEndpoint;
    std::optional<SshSessionHandler> sessionHandle;
    LIBSSH2_CHANNEL *libssh2Channel = nullptr;
    int pendingDirections = 0;
    State state = State::DISCONNECTED;
    Endpoint targetEndpoint;
};

using SshSocketPtr = std::shared_ptr<SshSocket>;

#endif //PROXY_OVER_SSH_SSHSOCKET_H
