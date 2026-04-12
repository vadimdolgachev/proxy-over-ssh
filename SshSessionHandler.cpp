//
// Created by vadim on 21.03.2026.
//

#include "SshSessionHandler.h"
#include "Constants.h"

SshSession::SshSession() : libSsh2Session(libssh2_session_init()) {
    if (libSsh2Session == nullptr) {
        throw std::runtime_error("libssh2_session_init() failed");
    }
    libssh2_session_set_blocking(libSsh2Session, 0);
    libssh2_keepalive_config(libSsh2Session, 1, Constants::SSH_KEEPALIVE_INTERVAL_SEC);
}

SshSession::~SshSession() {
    if (libSsh2Session != nullptr) {
        libssh2_session_free(libSsh2Session);
    }
}

SshSession::SshSession(SshSession &&handler) noexcept : libSsh2Session(std::exchange(handler.libSsh2Session, nullptr)) {
}

SshSession &SshSession::operator=(SshSession &&handler) noexcept {
    if (&handler != this) {
        if (libSsh2Session != nullptr) {
            libssh2_session_free(libSsh2Session);
        }
        libSsh2Session = std::exchange(handler.libSsh2Session, nullptr);
    }
    return *this;
}

int SshSession::handshake(const SocketPtr &socket) noexcept { // NOLINT(readability-make-member-function-const)
    return libssh2_session_handshake(libSsh2Session, socket->fd());
}

int SshSession::disconnect() noexcept { // NOLINT(readability-make-member-function-const)
    return libssh2_session_disconnect(libSsh2Session, "Normal shutdown");
}

int SshSession::blockDirections() noexcept { // NOLINT(readability-make-member-function-const)
    return libssh2_session_block_directions(libSsh2Session);
}

LIBSSH2_SESSION *SshSession::raw() const noexcept {
    return libSsh2Session;
}
