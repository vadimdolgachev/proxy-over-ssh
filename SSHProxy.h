//
// Created by vadim on 31.10.2025.
//

#ifndef SSHEPROXY_H
#define SSHEPROXY_H

#include <atomic>
#include <memory>
#include <optional>
#include <thread>

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

class SSHProxy {
public:
    explicit SSHProxy(const std::atomic_bool &stopSignalFlag);
    ~SSHProxy();

    void start(const ProxyConfig &proxyConfig);
    void requestStop() noexcept;
    void waitForFinish();

private:
    void mainLoop(const std::stop_token &stopToken);

    std::optional<ProxyConfig> config;
    std::optional<std::jthread> mainThread;
    const std::atomic_bool &stopSignalFlag;
};

#endif // SSHEPROXY_H
