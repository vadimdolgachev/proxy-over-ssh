//
// Created by vadim on 21.03.2026.
//

#ifndef PROXY_OVER_SSH_SESSIONPOOL_H
#define PROXY_OVER_SSH_SESSIONPOOL_H

#include <deque>
#include <mutex>

#include "SshSessionHandler.h"
#include "Constants.h"

class SessionPool {
public:
    explicit SessionPool(size_t maxSessions_ = Constants::SESSION_POOL_MAX_SIZE);

    ~SessionPool();

    SessionPool(const SessionPool &) = delete;

    SessionPool &operator=(const SessionPool &) = delete;

    SessionPool(SessionPool &&) = delete;

    SessionPool &operator=(SessionPool &&) = delete;

    std::optional<SshSessionHandler> acquire();

    void release(SshSessionHandler handler);

    void cleanup();

    void invalidate(const SshSessionHandler &handle);

private:
    enum class ValidationResult {
        VALID,
        NULL_COMPONENTS,
        INVALID_SOCKET_FD,
        SOCKET_OPT_FAILED,
        SOCKET_ERROR,
        SSH_KEEPALIVE_FAILED
    };

    static ValidationResult validateSessionDetailed(const SshSessionHandler &handle);

    static const char *validationResultToString(ValidationResult result);

    mutable std::mutex mutex;
    size_t maxSessions;
    std::deque<SshSessionHandler> sessions;
};

#endif // PROXY_OVER_SSH_SESSIONPOOL_H
