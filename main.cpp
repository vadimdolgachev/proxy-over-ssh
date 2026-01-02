#include <iostream>
#include <expected>
#include <unordered_map>
#include <string_view>
#include <charconv>
#include <csignal>

#include "SSHProxy.h"

std::expected<ProxyConfig, std::string> parseConfig(const int argc, char **argv) {
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
        auto [ptr, ec] = std::from_chars(v->data(),
                                         v->data() + v->size(),
                                         value);

        if (ec != std::errc{}) {
            return std::unexpected("Invalid integer value for " + std::string(key));
        }
        return value;
    };

    const auto sshUser = requireStr("--ssh-user");
    const auto sshHost = requireStr("--ssh-host");
    const auto sshPrivateKey = requireStr("--ssh-private-key");
    const auto sshPort = parseUint16("--ssh-port");
    const auto listenPort = parseUint16("--listen-port");

    if (!sshUser) {
        return std::unexpected(sshUser.error());
    }
    if (!sshHost) {
        return std::unexpected(sshHost.error());
    }
    if (!sshPrivateKey) {
        return std::unexpected(sshPrivateKey.error());
    }
    if (!sshPort) {
        return std::unexpected(sshPort.error());
    }
    if (!listenPort) {
        return std::unexpected(listenPort.error());
    }

    return ProxyConfig{
        .ssh = {
            .username = std::string(*sshUser),
            .host = std::string(*sshHost),
            .port = *sshPort,
            .privateKeyPath = std::string(*sshPrivateKey)
        },
        .listenPort = *listenPort,
    };
}

static std::atomic_bool stopSignalFlag = false;

extern "C" void onSignalTerm(int) {
    stopSignalFlag.store(true, std::memory_order_relaxed);
}

int main(const int argc, char **argv) {
    std::signal(SIGTERM, onSignalTerm);
    if (const auto config = parseConfig(argc, argv)) {
        if (const auto proxy = std::make_unique<SSHProxy>(stopSignalFlag); proxy->start(config.value())) {
            proxy->waitForFinish();
        } else {
            std::cerr << "Failed to start proxy" << std::endl;
            return 1;
        }
    } else {
        std::cerr << "Failed to parse arguments: " << config.error() << "\n";
    }
    std::cout << "Exit\n";
    return 0;
}
