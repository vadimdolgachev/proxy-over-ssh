#ifndef PROXY_OVER_SSH_CONSTANTS_H
#define PROXY_OVER_SSH_CONSTANTS_H

namespace Constants {
    constexpr size_t EPOLL_BATCH_SIZE = 16;
    constexpr size_t EPOLL_TIMEOUT_MS = 1'000;
    constexpr int BUSY_LOOP_THRESHOLD = 100;
    constexpr size_t BUSY_LOOP_CHECK_INTERVAL_MS = 100;

    constexpr size_t BUFFER_SIZE = 8192;
    constexpr size_t MAX_BUFFER_SIZE = 2 * BUFFER_SIZE;

    constexpr int IDLE_TIMEOUT_SEC = 30;
    constexpr int SSH_CONNECT_TIMEOUT_SEC = 30;

    constexpr size_t MAX_SOCKS5_METHODS = 16;
    constexpr size_t SOCKS5_MAX_REQUEST_SIZE = 262;

    constexpr long long NANOSECONDS_PER_SECOND = 1'000'000'000LL;

    constexpr size_t SESSION_POOL_MAX_SIZE = 25;
    constexpr int SESSION_VALIDATION_TIMEOUT_MS = 5000;
    constexpr int SSH_KEEPALIVE_INTERVAL_SEC = 30;
    constexpr int SSH_KEEPALIVE_MAX_COUNT = 3;
} // namespace Constants

#endif // PROXY_OVER_SSH_CONSTANTS_H
