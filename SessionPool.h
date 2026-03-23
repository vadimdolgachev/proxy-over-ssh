//
// Created by vadim on 21.03.2026.
//

#ifndef PROXY_OVER_SSH_SESSIONPOOL_H
#define PROXY_OVER_SSH_SESSIONPOOL_H

#include <mutex>

#include "SshSessionHandler.h"
#include "SSHProxy.h"

class SessionPool {
public:
    explicit SessionPool(size_t maxSessions_ = 25);

    ~SessionPool();

    SessionPool(const SessionPool &) = delete;

    SessionPool &operator=(const SessionPool &) = delete;

    SessionPool(SessionPool &&) = delete;

    SessionPool &operator=(SessionPool &&) = delete;

    std::optional<SshSessionHandler> acquire();

    void release(SshSessionHandler session);

    void cleanup();

    void invalidate(const SshSessionHandler &handle);

private:
    static bool validateSession(const SshSessionHandler &handle);

    mutable std::mutex mutex;
    size_t maxSessions;
    std::vector<SshSessionHandler> sessions;
};

#endif // PROXY_OVER_SSH_SESSIONPOOL_H
