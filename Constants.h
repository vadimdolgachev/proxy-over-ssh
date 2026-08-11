#ifndef PROXY_OVER_SSH_PROXY_CONSTANTS_H
#define PROXY_OVER_SSH_PROXY_CONSTANTS_H

#include <chrono>
#include <cstddef>

namespace Constants {
    constexpr size_t BUFFER_SIZE = 8192;

    constexpr int IDLE_TIMEOUT_SEC = 300;

    constexpr size_t SESSION_POOL_MAX_SIZE = 25;
    constexpr int SSH_KEEPALIVE_INTERVAL_SEC = 30;

    constexpr auto PRINT_STATS_INTERVAL = std::chrono::seconds(1);

    constexpr auto CLIENT_SETUP_TIMEOUT = std::chrono::seconds(30);
} // namespace Constants

#endif // PROXY_OVER_SSH_PROXY_CONSTANTS_H
