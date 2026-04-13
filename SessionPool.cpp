//
// Created by vadim on 21.03.2026.
//

#include <ranges>

#include <sys/socket.h>
#include <unistd.h>

#include "SessionPool.h"
#include "Logger.h"
#include "Socket.h"

SessionPool::SessionPool(const size_t maxSessions_) : maxSessions(maxSessions_) {
    log_d("SessionPool created with max {} sessions\n", maxSessions);
}

SessionPool::~SessionPool() {
    cleanup();
}

void SessionPool::invalidate(const SshSessionHandler &handle) {
    std::lock_guard lock(mutex);
    if (handle.sshSession == nullptr) {
        return;
    }
    if (const auto it = std::ranges::find_if(sessions, [&handle](const SshSessionHandler &sh) {
        return sh.sshSession != nullptr && sh.sshSession->raw() == handle.sshSession->raw();
    }); it != sessions.end()) {
        sessions.erase(it);
    }
}

std::optional<SshSessionHandler> SessionPool::acquire() {
    std::lock_guard lock(mutex);
    log_v("SessionPool: acquire, size={}\n", sessions.size());
    while (!sessions.empty()) {
        auto handle = std::move(sessions.back());
        sessions.pop_back();
        const auto result = validateSessionDetailed(handle);
        if (result == ValidationResult::VALID) {
            handle.lastUsed = std::chrono::steady_clock::now();
            return handle;
        }
        log_v("SessionPool: Discarding invalid session (socket={}, reason={})\n",
              handle.tcpSocket != nullptr ? handle.tcpSocket->fd() : -1,
              validationResultToString(result));
    }
    log_v("SessionPool: No session available in pool\n");
    return std::nullopt;
}

void SessionPool::release(SshSessionHandler handler) {
    std::lock_guard lock(mutex);
    if (handler.sshSession == nullptr || handler.tcpSocket == nullptr) {
        log_v("SessionPool: Discarding empty session\n");
        return;
    }

    if (sessions.size() > maxSessions) {
        sessions.pop_front();
    }
    sessions.push_back(std::move(handler));
}

void SessionPool::cleanup() {
    std::lock_guard lock(mutex);
    sessions.clear();
}

SessionPool::ValidationResult SessionPool::validateSessionDetailed(const SshSessionHandler &handle) {
    if (handle.sshSession == nullptr || handle.tcpSocket == nullptr) {
        return ValidationResult::NULL_COMPONENTS;
    }

    if (handle.tcpSocket->fd() < 0) {
        return ValidationResult::INVALID_SOCKET_FD;
    }

    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(handle.tcpSocket->fd(), SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        return ValidationResult::SOCKET_OPT_FAILED;
    }
    if (error != 0) {
        return ValidationResult::SOCKET_ERROR;
    }

    // Check if socket is still connected using peek read
    char buf;
    const ssize_t r = recv(handle.tcpSocket->fd(), &buf, 1, MSG_PEEK | MSG_DONTWAIT);
    if (r == 0) {
        return ValidationResult::SOCKET_CLOSED;
    }
    // r > 0 means data available (still connected), r < 0 with EAGAIN means no data but connected
    if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        return ValidationResult::SOCKET_ERROR;
    }

    return ValidationResult::VALID;
}

const char *SessionPool::validationResultToString(const ValidationResult result) {
    switch (result) {
        case ValidationResult::VALID: return "VALID";
        case ValidationResult::NULL_COMPONENTS: return "NULL_COMPONENTS";
        case ValidationResult::INVALID_SOCKET_FD: return "INVALID_SOCKET_FD";
        case ValidationResult::SOCKET_OPT_FAILED: return "SOCKET_OPT_FAILED";
        case ValidationResult::SOCKET_ERROR: return "SOCKET_ERROR";
        case ValidationResult::SOCKET_CLOSED: return "SOCKET_CLOSED";
        default: return "UNKNOWN";
    }
}
