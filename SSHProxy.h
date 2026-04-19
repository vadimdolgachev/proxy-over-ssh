//
// Created by vadim on 31.10.2025.
//

#ifndef PROXY_OVER_SSH_SSHEPROXY_H
#define PROXY_OVER_SSH_SSHEPROXY_H

#include <atomic>
#include <functional>
#include <optional>
#include <string>
#include <thread>

#include "BackendSocket.h"
#include "CancellationToken.h"

struct SSHConfig final {
    std::string username;
    std::string host;
    std::uint16_t port;
    std::optional<std::string> privateKeyPath = {};
    std::optional<std::string> privateKeyData = {};
};

struct ProxyConfig final {
    BackendFactory backendFactory;
    std::uint16_t listenPort;
};

using StartCallback = std::function<void()>;
using FinishCallback = std::function<void()>;
using ErrorCallback = std::function<void(int)>;

class SSHProxy {
public:
    explicit SSHProxy(CancellationTokenSource &cts_);

    ~SSHProxy();

    void start(const ProxyConfig &proxyConfig,
               const std::optional<StartCallback> &startCb,
               const std::optional<FinishCallback> &stopCb);

    void requestStop() noexcept;

    void waitForFinish();

private:
    void mainLoop(const std::optional<StartCallback> &startCb, const std::optional<FinishCallback> &stopCb);

    std::optional<ProxyConfig> config;
    std::optional<std::jthread> mainThread;
    CancellationTokenSource &cts;
};

#endif // PROXY_OVER_SSH_SSHEPROXY_H
