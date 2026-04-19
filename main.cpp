#include <algorithm>
#include <charconv>
#include <csignal>
#include <expected>
#include <format>
#include <memory>
#include <string_view>
#include <unordered_map>

#include "BackendSocket.h"
#include "CancellationToken.h"
#include "Logger.h"
#include "SSHProxy.h"
#include "SessionPool.h"
#include "SshSocket.h"

namespace {
    std::string parsePrivateKey(const std::string_view privateKey) {
        using namespace std::string_view_literals;
        auto content = std::string(privateKey);
        if (content.starts_with("$")) {
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
            auto [ptr, ec] = std::from_chars(v->data(), v->data() + v->size(), value);

            if (ec != std::errc{}) {
                return std::unexpected("Invalid integer value for " + std::string(key));
            }
            return value;
        };

        const auto sshUser = requireStr("--ssh-user");
        const auto sshHost = requireStr("--ssh-host");
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
                .privateKeyPath = sshPrivateKeyPathOpt,
                .privateKeyData = sshPrivateKeyOpt,
            },
            .listenPort = *listenPort,
        };
    }

    CancellationTokenSource cancellationTokenSource;
} // namespace


extern "C" void onSignalTerm(int) {
    cancellationTokenSource.requestStop();
}

int main(const int argc, char **argv) {
    std::signal(SIGTERM, onSignalTerm);
    if (const auto appConfig = parseConfig(argc, argv)) {
        auto sessionPool = std::make_shared<SessionPool>(25);
        const auto factory = [sshConfig = appConfig->ssh, sessionPool](const Endpoint &) -> BackendSocketPtr {
            return std::make_shared<SshSocket>(sshConfig, sessionPool);
        };

        ProxyConfig proxyConfig {
            .backendFactory = factory,
            .listenPort = appConfig->listenPort,
        };

        auto proxy = std::make_unique<SSHProxy>(cancellationTokenSource);
        proxy->start(proxyConfig, std::nullopt, std::nullopt);
        proxy->waitForFinish();
    } else {
        log_e("Failed to parse arguments: {}\n", appConfig.error());
    }
    log_d("Exit\n");
    return 0;
}
