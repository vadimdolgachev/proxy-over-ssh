#ifndef PROXY_OVER_SSH_CONSTANTS_H
#define PROXY_OVER_SSH_CONSTANTS_H

namespace Constants {
    constexpr size_t EPOLL_BATCH_SIZE = 16;
    constexpr size_t EPOLL_TIMEOUT_MS = 1'000;

    constexpr size_t BUFFER_SIZE = 8192;

    constexpr int IDLE_TIMEOUT_SEC = 30;

    constexpr long long NANOSECONDS_PER_SECOND = 1'000'000'000LL;

    constexpr size_t SESSION_POOL_MAX_SIZE = 25;
    constexpr int SSH_KEEPALIVE_INTERVAL_SEC = 30;

    constexpr size_t THREAD_POOL_SIZE = 4;
} // namespace Constants

#endif // PROXY_OVER_SSH_CONSTANTS_H
