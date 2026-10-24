#include <algorithm>
#include <atomic>
#include <charconv>
#include <csignal>
#include <expected>
#include <format>
#include <memory>
#include <string_view>
#include <unordered_map>

#include "BackendSocket.h"
#include "ByeDpiRuntime.h"
#include "CancellationToken.h"
#include "Logger.h"
#include "SSHProxy.h"
#include "SessionPool.h"
#include "SshSocket.h"

using namespace CoroLite;

namespace {
    std::string parsePrivateKey(const std::string_view privateKey) {
        using namespace std::string_view_literals;
        auto content = std::string(privateKey);
        if (content.starts_with('$')) {
            for (const auto pattern: {"$"sv, "{"sv, "}"sv}) {
                size_t pos = 0;
                while ((pos = content.find(pattern, pos)) != std::string::npos) {
                    content.replace(pos, pattern.length(), "");
                    pos += 1;
                }
            }
            if (const auto env = std::getenv(content.c_str())) {
                content = env;
            } else {
                throw std::runtime_error(std::format("Env variable '{}' not found", content));
            }
        }
        size_t pos = 0;
        while ((pos = content.find("\\n", pos)) != std::string::npos) {
            content.replace(pos, 2, "\n");
            pos += 1;
        }
        return std::format("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----", content);
    }

    struct AppConfig {
        SSHConfig ssh;
        std::uint16_t listenPort;
        std::optional<std::string> byeDpiArgs;
    };

    std::expected<AppConfig, std::string> parseConfig(const int argc, char **argv) {
        using namespace std::string_view_literals;

        if ((argc - 1) % 2 != 0) {
            return std::unexpected("Each option must have a value");
        }

        std::unordered_map<std::string_view, std::string_view> args;

        for (int i = 1; i < argc; i += 2) {
            args.emplace(argv[i], argv[i + 1]);
        }

        const auto requireStr = [&](const std::string_view key) -> std::expected<std::string_view, std::string> {
            if (const auto it = args.find(key); it != args.end()) {
                return it->second;
            }

            return std::unexpected("Missing required parameter: " + std::string(key));
        };

        const auto parseUint16 = [&](const std::string_view key) -> std::expected<std::uint16_t, std::string> {
            auto v = requireStr(key);
            if (!v) {
                return std::unexpected(v.error());
            }

            std::uint16_t value{};
            if (const auto [ptr, ec] = std::from_chars(v->data(), v->data() + v->size(), value); ec != std::errc{}) {
                return std::unexpected("Invalid integer value for " + std::string(key));
            }
            return value;
        };

        const auto sshUser = requireStr("--ssh-user");
        const auto sshHost = requireStr("--ssh-host");
        const auto sshHostKeySha256 = requireStr("--ssh-host-key-sha256");
        const auto sshPrivateKeyPath = requireStr("--ssh-private-key-path");
        const auto sshPrivateKey = requireStr("--ssh-private-key");
        const auto sshPort = parseUint16("--ssh-port");
        const auto listenPort = parseUint16("--listen-port");

        if (!sshUser) {
            return std::unexpected(sshUser.error());
        }
        if (!sshHost) {
            return std::unexpected(sshHost.error());
        }
        if (!sshHostKeySha256) {
            return std::unexpected(sshHostKeySha256.error());
        }
        if (!sshPrivateKey && !sshPrivateKeyPath) {
            return std::unexpected("Either --ssh-private-key or --ssh-private-key-path must be provided");
        }
        std::optional<std::string> sshPrivateKeyOpt;
        if (sshPrivateKey) {
            sshPrivateKeyOpt = parsePrivateKey(*sshPrivateKey);
        }
        std::optional<std::string> sshPrivateKeyPathOpt;
        if (sshPrivateKeyPath) {
            sshPrivateKeyPathOpt = std::string(*sshPrivateKeyPath);
        }
        if (!sshPort) {
            return std::unexpected(sshPort.error());
        }
        if (!listenPort) {
            return std::unexpected(listenPort.error());
        }

        return AppConfig{
            .ssh = {
                .username = std::string(*sshUser),
                .host = std::string(*sshHost),
                .port = *sshPort,
                .hostKeySha256 = std::string(*sshHostKeySha256),
                .privateKeyPath = sshPrivateKeyPathOpt,
                .privateKeyData = sshPrivateKeyOpt,
            },
            .listenPort = *listenPort,
            .byeDpiArgs = args.contains("--byedpi-args")
                                  ? std::optional<std::string>(args.at("--byedpi-args"))
                                  : std::nullopt,
        };
    }

    CancellationTokenSource cancellationTokenSource;
} // namespace


extern "C" void onSignalTerm(int) {
    cancellationTokenSource.requestStop();
}

int main(const int argc, char **argv) {
    std::signal(SIGTERM, onSignalTerm);
    std::signal(SIGINT, onSignalTerm);
    std::atomic_bool byeDpiFailed = false;
    try {
        auto appConfig = parseConfig(argc, argv);
        if (!appConfig) {
            log_e("Failed to parse arguments: {}\n", appConfig.error());
            return 1;
        }
        if (appConfig->byeDpiArgs) {
            appConfig->ssh.byeDpi = std::make_shared<ByeDpiRuntime>(
                    *appConfig->byeDpiArgs, ByeDpiRuntime::SocketProtector{}, [&](int) {
                        byeDpiFailed.store(true);
                        cancellationTokenSource.requestStop();
                    });
        }
        auto sessionPool = std::make_shared<SessionPool>(Constants::SESSION_POOL_MAX_SIZE);
        const auto factory = [sshConfig = appConfig->ssh, sessionPool](const Endpoint &) -> BackendSocketPtr {
            return std::make_shared<SshSocket>(sshConfig, sessionPool);
        };

        const ProxyConfig proxyConfig {
            .backendFactory = factory,
            .listenPort = appConfig->listenPort,
        };

        const auto proxy = std::make_unique<SSHProxy>(cancellationTokenSource);
        proxy->start(proxyConfig, std::nullopt, std::nullopt);
        proxy->waitForFinish();
        if (appConfig->ssh.byeDpi) {
            appConfig->ssh.byeDpi->requestStop();
        }
    } catch (const std::exception &error) {
        log_e("Failed to run proxy: {}\n", error.what());
        return 1;
    }
    log_d("Exit\n");
    return byeDpiFailed.load() ? 1 : 0;
}
