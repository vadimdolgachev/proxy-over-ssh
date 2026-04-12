//
// Created by vadim on 21.03.2026.
//

#ifndef PROXY_OVER_SSH_SSHSESSIONHANDLER_H
#define PROXY_OVER_SSH_SSHSESSIONHANDLER_H

#include <libssh2.h>

#include "Socket.h"

class SshSession final {
public:
    SshSession();

    ~SshSession();

    SshSession(const SshSession &handler) = delete;

    SshSession &operator=(const SshSession &handler) = delete;

    SshSession(SshSession &&handler) noexcept;

    SshSession &operator=(SshSession &&handler) noexcept;

    [[nodiscard]] int handshake(const SocketPtr &socket) noexcept;

    [[nodiscard]] int disconnect() noexcept;

    [[nodiscard]] int blockDirections() noexcept;

    [[nodiscard]] LIBSSH2_SESSION *raw() const noexcept;

private:
    LIBSSH2_SESSION *libSsh2Session;
};

struct SshSessionHandler final {
    std::unique_ptr<SshSession> sshSession;
    SocketPtr tcpSocket;
    std::chrono::steady_clock::time_point lastUsed;
};

#endif //PROXY_OVER_SSH_SSHSESSIONHANDLER_H
