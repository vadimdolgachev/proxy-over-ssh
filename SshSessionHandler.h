//
// Created by vadim on 21.03.2026.
//

#ifndef PROXY_OVER_SSH_SSHSESSIONHANDLER_H
#define PROXY_OVER_SSH_SSHSESSIONHANDLER_H

#include <libssh2.h>

#include "Socket.h"

class SshSession final {
public:
    SshSession() : libssh2Session(libssh2_session_init()) {
        if (libssh2Session == nullptr) {
            throw std::runtime_error("libssh2_session_init() failed");
        }
        libssh2_session_set_blocking(libssh2Session, 0);
        libssh2_session_set_timeout(libssh2Session, 30000);
    }

    ~SshSession() {
        // std::cout << "~SshSession libssh2Session=" << libssh2Session << std::endl;
        if (libssh2Session) {
            libssh2_session_free(libssh2Session);
        }
    }

    SshSession(const SshSession &handler) = delete;

    SshSession &operator=(const SshSession &handler) = delete;

    SshSession(SshSession &&handler) noexcept : libssh2Session(std::exchange(handler.libssh2Session, nullptr)) {
    }

    SshSession &operator=(SshSession &&handler) noexcept {
        if (handler.libssh2Session != nullptr) {
            handler.disconnect();
            libssh2_session_free(handler.libssh2Session);
        }
        libssh2Session = handler.libssh2Session;
        return *this;
    }

    [[nodiscard]] int handshake(const SocketPtr &socket) noexcept {
        return libssh2_session_handshake(libssh2Session, socket->fd());
    }

    int disconnect() noexcept {
        return libssh2_session_disconnect(libssh2Session, "Normal shutdown");
    }

    [[nodiscard]] int blockDirections() noexcept {
        return libssh2_session_block_directions(libssh2Session);
    }

    [[nodiscard]] LIBSSH2_SESSION *raw() const noexcept {
        return libssh2Session;
    }

private:
    LIBSSH2_SESSION *libssh2Session;
};

struct SshSessionHandler final {
    std::unique_ptr<SshSession> sshSession;
    SocketPtr tcpSocket;
    std::chrono::steady_clock::time_point lastUsed;
};

#endif //PROXY_OVER_SSH_SSHSESSIONHANDLER_H
