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
#include "SshHostKey.h"
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
        SSH_HOST_VERIFIED,
        SSH_AUTHENTICATED,
        CHANNEL_CREATED,
        ERROR
    };

    SshSocket(SSHConfig sshConfig_, const std::shared_ptr<SessionPool> &sessionPool_);

    SshSocket(const SshSocket &) = delete;

    SshSocket &operator=(const SshSocket &) = delete;

    ~SshSocket() override;

    [[nodiscard]] CoroLite::CoroTask<ResultCode> connectAsync(const CoroLite::Endpoint &targetEndpoint_,
                                                              CoroLite::CancellationTokenOpt ct) override;

    [[nodiscard]] CoroLite::CoroTask<size_t> readAsync(std::span<uint8_t> buffer,
                                                       CoroLite::CancellationTokenOpt ct) override;

    [[nodiscard]] CoroLite::CoroTask<size_t> writeAsync(std::span<const uint8_t> data,
                                                        CoroLite::CancellationTokenOpt ct) override;

    [[nodiscard]] int fd() const noexcept override;

    [[nodiscard]] bool isEof() const noexcept override;

    void close() noexcept override;

private:
    friend struct SshConnectAwaiter;
    friend struct SshFdWaitAwaiter;
    friend struct SshSocketAwaiterBase;

    ResultCode tryTcpConnect();

    ResultCode performHandshake();

    ResultCode verifyHostKey();

    ResultCode performAuthentication();

    ResultCode createChannel();

    [[nodiscard]] uint32_t getPollEvents(uint32_t defaultEvents) const;

    static uint32_t computePollEvents(int directions, uint32_t defaultEvents) noexcept;

    ResultCode advanceConnection();

    ResultCode handleLibSsh2Result(int rc, const char *operation);

    ResultCode handleLibSsh2ChannelResult(const LIBSSH2_CHANNEL *channel,
                                          const char *operation,
                                          const std::string &host);

    ResultCode tryConnectNonBlocking();

    std::shared_ptr<SessionPool> sessionPool;
    SSHConfig sshConfig;
    SshHostKey::Sha256Digest expectedHostKeySha256 = {};
    CoroLite::Endpoint sshServerEndpoint;
    std::optional<SshSessionHandler> sessionHandle;
    LIBSSH2_CHANNEL *libSsh2Channel = nullptr;
    int pendingDirections = 0;
    State connectionState = State::DISCONNECTED;
    CoroLite::Endpoint targetEndpoint;
    mutable std::mutex sshMutex;
};

struct SshSocketAwaiterBase : CoroLite::SchedulerAware<CoroLite::EpollScheduler> {
protected:
    SshSocketAwaiterBase(std::shared_ptr<SshSocket> socket_,
                         const CoroLite::CancellationTokenOpt &cancellationToken_);

    void onSuspend(std::coroutine_handle<> h, uint32_t events);

    void onResume();

    std::shared_ptr<SshSocket> socket;
    const CoroLite::CancellationTokenOpt &cancellationToken;
    std::coroutine_handle<> handle;
};

struct SshConnectAwaiter final : SshSocketAwaiterBase {
    SshConnectAwaiter(std::shared_ptr<SshSocket> socket_,
                      CoroLite::Endpoint targetEndpoint_,
                      const CoroLite::CancellationTokenOpt &cancellationToken_);

    [[nodiscard]] bool await_ready() const;

    void await_suspend(std::coroutine_handle<> h);

    void await_resume();

private:
    CoroLite::Endpoint targetEndpoint;
    mutable int connectErrno = 0;
};

struct SshFdWaitAwaiter final : SshSocketAwaiterBase {
    SshFdWaitAwaiter(std::shared_ptr<SshSocket> socket_,
                     const CoroLite::CancellationTokenOpt &cancellationToken_,
                     uint32_t events_);

    [[nodiscard]] bool await_ready() const noexcept;

    void await_suspend(std::coroutine_handle<> h);

    void await_resume();

private:
    uint32_t events;
};

using SshSocketPtr = std::shared_ptr<SshSocket>;

#endif // PROXY_OVER_SSH_SSHSOCKET_H
