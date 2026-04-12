//
// Created by vadim on 21.03.2026.
//

#include <ranges>

#include <libssh2.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include "SessionPool.h"
#include "Logger.h"
#include "Socket.h"

SessionPool::SessionPool(const size_t maxSessions_) : maxSessions(maxSessions_) {
    log_d("SessionPool created with max {} sessions\n", maxSessions);
}

SessionPool::~SessionPool() {
    std::lock_guard lock(mutex);
    log_d("SessionPool destroying {} sessions\n", sessions.size());
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
        const ValidationResult result = validateSessionDetailed(handle);
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

    const int originalFlags = fcntl(handle.tcpSocket->fd(), F_GETFL, 0);
    if (originalFlags == -1) {
        return ValidationResult::SOCKET_OPT_FAILED;
    }
    if (fcntl(handle.tcpSocket->fd(), F_SETFL, originalFlags | O_NONBLOCK) == -1) {
        return ValidationResult::SOCKET_OPT_FAILED;
    }

    const int keepaliveResult = libssh2_keepalive_send(handle.sshSession->raw(), nullptr);

    fcntl(handle.tcpSocket->fd(), F_SETFL, originalFlags);

    if (keepaliveResult == LIBSSH2_ERROR_EAGAIN) {
        return ValidationResult::VALID;
    }
    if (keepaliveResult < 0) {
        return ValidationResult::SSH_KEEPALIVE_FAILED;
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
        case ValidationResult::SSH_KEEPALIVE_FAILED: return "SSH_KEEPALIVE_FAILED";
        default: return "UNKNOWN";
    }
}
