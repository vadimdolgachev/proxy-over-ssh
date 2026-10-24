//
// Created by vadim on 21.03.2026.
//

#include <chrono>
#include <string_view>

#include "Constants.h"
#include "Logger.h"
#include "SshSessionHandler.h"

using namespace CoroLite;

namespace {
    void onServerDisconnect(LIBSSH2_SESSION *,
                            int reason,
                            const char *message,
                            int length,
                            const char *,
                            int,
                            void **) noexcept {
        try {
            const auto detail = message != nullptr && length > 0
                                        ? std::string_view(message, static_cast<std::size_t>(length)).substr(0, 512)
                                        : std::string_view{};
            log_e("SSH server disconnect: reason={}, message='{}'\n", reason, detail);
        } catch (...) {
            // Never propagate a C++ logging exception through a libssh2 callback.
        }
    }
} // namespace

SshSession::SshSession() :
    libSsh2Session(libssh2_session_init()) {
    if (libSsh2Session == nullptr) {
        throw std::runtime_error("libssh2_session_init() failed");
    }
    libssh2_session_set_blocking(libSsh2Session, 0);
    libssh2_session_callback_set2(libSsh2Session, LIBSSH2_CALLBACK_DISCONNECT,
                                  reinterpret_cast<libssh2_cb_generic *>(onServerDisconnect));
    libssh2_keepalive_config(libSsh2Session, 1, Constants::SSH_KEEPALIVE_INTERVAL_SEC);
}

SshSession::~SshSession() {
    if (libSsh2Session != nullptr) {
        libssh2_session_free(libSsh2Session);
    }
}

SshSession::SshSession(SshSession &&handler) noexcept :
    libSsh2Session(std::exchange(handler.libSsh2Session, nullptr)) {
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
