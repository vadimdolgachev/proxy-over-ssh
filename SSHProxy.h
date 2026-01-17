//
// Created by vadim on 31.10.2025.
//

#ifndef SSHEPROXY_H
#define SSHEPROXY_H

#include <atomic>
#include <memory>
#include <optional>
#include <thread>
#include <unordered_map>
#include <queue>

enum class ResultCode {
    Ok,
    ErrAgain,
    ErrIO,
    ErrTimeout,
    ErrInvalidPrivateKey,
    ErrUnknown,
};

struct SSHConfig final {
    std::string username;
    std::string host;
    std::uint16_t port;
    std::optional<std::string> privateKeyPath = {};
    std::optional<std::string> privateKeyData = {};
};

struct ProxyConfig final {
    SSHConfig ssh;
    std::uint16_t listenPort;
};

class EPollManager;
struct ClientContext;
class SSH2Session;

class SSHProxy {
public:
    explicit SSHProxy(const std::atomic_bool &stopSignalFlag);
    ~SSHProxy();

    void start(const ProxyConfig &proxyConfig);
    void requestStop() noexcept;
    void waitForFinish();

private:
    void mainLoop(const std::stop_token &stopToken);
    void handleClientForRead(const std::shared_ptr<ClientContext> &clientCtx);
    void handleClientForWrite(const std::shared_ptr<ClientContext> &clientCtx);
    void handleSshRead(const std::shared_ptr<ClientContext> &clientCtx);
    void handleSshWrite(const std::shared_ptr<ClientContext> &clientCtx);
    [[nodiscard]] ResultCode sshRead(const std::shared_ptr<ClientContext> &clientCtx);
    [[nodiscard]] static ResultCode sshWrite(const std::shared_ptr<ClientContext> &clientCtx);
    [[nodiscard]] ResultCode sendToClient(const std::shared_ptr<ClientContext> &clientCtx);
    [[nodiscard]] ResultCode setupEpoll();
    [[nodiscard]] ResultCode connectToSshServer(const std::shared_ptr<ClientContext> &clientCtx);
    void setupSshConnection(const std::shared_ptr<ClientContext> &clientCtx);
    [[nodiscard]] bool setupLocalServer();
    void handleNewClientConnection();
    void handleSocks5Handshake(const std::shared_ptr<ClientContext> &clientCtx);
    void handleSocks5Request(const std::shared_ptr<ClientContext> &clientCtx);
    [[nodiscard]] ResultCode createSshChannel(const std::shared_ptr<ClientContext> &clientCtx);
    void closeConnection(const std::shared_ptr<ClientContext> &clientCtx);
    [[nodiscard]] ResultCode handleSessionAuthenticateClient(const std::shared_ptr<ClientContext> &clientCtx) const;
    void closeAllConnection();
    [[nodiscard]] static ResultCode closeSshChannel(const std::shared_ptr<ClientContext> &clientCtx);
    [[nodiscard]] std::optional<std::shared_ptr<ClientContext>> getClientCtxBySshFd(int sshFd);
    [[nodiscard]] std::optional<std::shared_ptr<ClientContext>> getClientCtxByFd(int clientFd);

    std::optional<ProxyConfig> config;
    std::shared_ptr<EPollManager> epollManager;
    int serverFd;
    std::unordered_map<int, std::shared_ptr<ClientContext>> clients;
    std::optional<std::jthread> mainThread;
    std::unordered_map<int, int> sshToClientSockets;
    std::deque<std::unique_ptr<SSH2Session>> sshSessionObjectPool;
    const std::atomic_bool &stopSignalFlag;
};

#endif // SSHEPROXY_H
