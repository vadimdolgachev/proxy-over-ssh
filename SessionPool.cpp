//
// Created by vadim on 21.03.2026.
//

#include "SessionPool.h"

#include <sys/socket.h>
#include <unistd.h>
#include <ranges>

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
    if (const auto it = std::ranges::find_if(sessions, [&handle](const SshSessionHandler &sh) {
        return sh.sshSession->raw() == handle.sshSession->raw();
    }); it != sessions.end()) {
        sessions.erase(it);
    }
}

std::optional<SshSessionHandler> SessionPool::acquire() {
    std::lock_guard lock(mutex);
    log_v("SessionPool: pool size={}\n", sessions.size());
    while (!sessions.empty()) {
        auto handle = std::move(sessions.back());
        sessions.pop_back();
        if (validateSession(handle)) {
            handle.lastUsed = std::chrono::steady_clock::now();
            return handle;
        }
        log_v("SessionPool: Error socket validation!\n");
    }
    log_v("SessionPool: No session available in pool\n");
    return std::nullopt;
}

void SessionPool::release(SshSessionHandler session) {
    std::lock_guard lock(mutex);
    sessions.push_back(std::move(session));
    log_v("SessionPool: Released session size {}\n", sessions.size());
}

void SessionPool::cleanup() {
    std::lock_guard lock(mutex);
    sessions.clear();
}

bool SessionPool::validateSession(const SshSessionHandler &handle) {
    if (!handle.sshSession || handle.tcpSocket->fd() < 0) {
        return false;
    }

    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(handle.tcpSocket->fd(), SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        return false;
    }

    std::cout << "validateSession: socket: " << handle.tcpSocket->fd() << ", error:" << error << std::endl;
    return error == 0;
}
