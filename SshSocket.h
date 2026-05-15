//
// Created by vadim on 28.01.2026.
//

#ifndef PROXY_OVER_SSH_SSHSOCKET_H
#define PROXY_OVER_SSH_SSHSOCKET_H

#include <memory>
#include <mutex>
#include <optional>
#include <span>

#include "libssh2.h"

#include "BackendSocket.h"
#include "CoroTask.h"
#include "Endpoint.h"
#include "SSHProxy.h"
#include "SessionPool.h"
#include "SshSessionHandler.h"

class SshSocket;
struct SshConnectAwaiter;
struct SshFdWaitAwaiter;
struct SshSocketAwaiterBase;

class SshSocket : public IBackendSocket,
                  public std::enable_shared_from_this<SshSocket> {
public:
    enum class State {
        DISCONNECTED,
        TCP_CONNECTED,
        SSH_HANDSHAKE,
        SSH_AUTHENTICATED,
        CHANNEL_CREATED,
        ERROR
    };

    SshSocket(SSHConfig sshConfig_, const std::shared_ptr<SessionPool> &sessionPool_);

    SshSocket(const SshSocket &) = delete;

    SshSocket &operator=(const SshSocket &) = delete;

    ~SshSocket() override;

    [[nodiscard]] CoroTask<ResultCode> connectAsync(const Endpoint &targetEndpoint_, CancellationTokenOpt ct) override;

    [[nodiscard]] CoroTask<size_t> readAsync(std::span<uint8_t> buffer, CancellationTokenOpt ct) override;

    [[nodiscard]] CoroTask<size_t> writeAsync(std::span<const uint8_t> data, CancellationTokenOpt ct) override;

    [[nodiscard]] int fd() const noexcept override;

    [[nodiscard]] bool isEof() const noexcept override;

    void close() noexcept override;

private:
    friend struct SshConnectAwaiter;
    friend struct SshFdWaitAwaiter;
    friend struct SshSocketAwaiterBase;

    ResultCode tryTcpConnect();

    ResultCode performHandshake();

    ResultCode performAuthentication();

    ResultCode createChannel();

    int getBlockDirections() const;

    static uint32_t computePollEvents(int directions, uint32_t defaultEvents);

    ResultCode advanceConnection();

    ResultCode handleLibSsh2Result(int rc, const char *operation);

    ResultCode handleLibSsh2ChannelResult(const LIBSSH2_CHANNEL *channel,
                                          const char *operation,
                                          const std::string &host);

    ResultCode tryConnectNonBlocking();

    std::shared_ptr<SessionPool> sessionPool;
    SSHConfig sshConfig;
    Endpoint sshServerEndpoint;
    std::optional<SshSessionHandler> sessionHandle;
    LIBSSH2_CHANNEL *libSsh2Channel = nullptr;
    int pendingDirections = 0;
    State connectionState = State::DISCONNECTED;
    Endpoint targetEndpoint;
    std::mutex sshMutex;
};

struct SshSocketAwaiterBase : SchedulerAware<EpollScheduler> {
protected:
    SshSocketAwaiterBase(std::shared_ptr<SshSocket> socket_,
                         const CancellationTokenOpt &cancellationToken_);

    [[nodiscard]] uint32_t computePollEvents(uint32_t defaultEvents) const;

    void onSuspend(std::coroutine_handle<> h, uint32_t defaultEvents);

    void onResume();

    std::shared_ptr<SshSocket> socket;
    const CancellationTokenOpt &cancellationToken;
    std::coroutine_handle<> handle;
};

struct SshConnectAwaiter final : SshSocketAwaiterBase {
    SshConnectAwaiter(std::shared_ptr<SshSocket> socket_,
                      Endpoint targetEndpoint_,
                      const CancellationTokenOpt &cancellationToken_);

    [[nodiscard]] bool await_ready() const noexcept;

    void await_suspend(std::coroutine_handle<> h);

    void await_resume();

private:
    Endpoint targetEndpoint;
    mutable int connectErrno = 0;
};

struct SshFdWaitAwaiter final : SshSocketAwaiterBase {
    SshFdWaitAwaiter(std::shared_ptr<SshSocket> socket_,
                     const CancellationTokenOpt &cancellationToken_);

    [[nodiscard]] bool await_ready() const noexcept;

    void await_suspend(std::coroutine_handle<> h);

    void await_resume();
};

using SshSocketPtr = std::shared_ptr<SshSocket>;

#endif // PROXY_OVER_SSH_SSHSOCKET_H
