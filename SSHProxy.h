//
// Created by vadim on 31.10.2025.
//

#ifndef PROXY_OVER_SSH_SSHEPROXY_H
#define PROXY_OVER_SSH_SSHEPROXY_H

#include <atomic>
#include <optional>
#include <thread>
#include <string>
#include <functional>

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

class SSHProxy {
public:
    explicit SSHProxy(CancellationTokenSource &cts_);

    ~SSHProxy();

    void start(const ProxyConfig &proxyConfig);

    void requestStop() noexcept;

    void waitForFinish();

private:
    void mainLoop();

    std::optional<ProxyConfig> config;
    std::optional<std::jthread> mainThread;
    CancellationTokenSource &cts;
};

#endif // PROXY_OVER_SSH_SSHEPROXY_H
