#include "SshConStateMachine.h"

#include <libssh2.h>

SshConStateMachine::State SshConStateMachine::getState() const noexcept {
    return state;
}

void SshConStateMachine::setState(const State newState) noexcept {
    state = newState;
}

bool SshConStateMachine::isTerminal() const noexcept {
    return state == State::CHANNEL_CREATED || state == State::ERROR;
}

ResultCode SshConStateMachine::advance(Context &context, int *const pendingDirections) {
    switch (state) {
        case State::DISCONNECTED: {
            const auto rc = context.tryTcpConnect();
            if (rc == ResultCode::ErrAgain) {
                if (pendingDirections != nullptr) {
                    *pendingDirections = LIBSSH2_SESSION_BLOCK_OUTBOUND;
                }
                return ResultCode::ErrAgain;
            }
            if (rc == ResultCode::Ok) {
                state = State::TCP_CONNECTED;
            } else {
                state = State::ERROR;
            }
            return rc;
        }
        case State::TCP_CONNECTED: {
            const auto rc = context.performHandshake();
            if (rc == ResultCode::Ok) {
                state = State::SSH_HANDSHAKE;
            } else if (rc == ResultCode::ErrAgain) {
                return rc; // pendingDirections set by context
            } else {
                state = State::ERROR;
            }
            return rc;
        }
        case State::SSH_HANDSHAKE: {
            const auto rc = context.performAuthentication();
            if (rc == ResultCode::Ok) {
                state = State::SSH_AUTHENTICATED;
            } else if (rc == ResultCode::ErrAgain) {
                return rc;
            } else {
                state = State::ERROR;
            }
            return rc;
        }
        case State::SSH_AUTHENTICATED: {
            const auto rc = context.createChannel();
            if (rc == ResultCode::Ok) {
                state = State::CHANNEL_CREATED;
            } else if (rc == ResultCode::ErrAgain) {
                return rc;
            } else {
                state = State::ERROR;
            }
            return rc;
        }
        case State::CHANNEL_CREATED:
            return ResultCode::Ok;
        case State::ERROR:
            return ResultCode::ErrUnknown;
    }
    return ResultCode::ErrUnknown;
}
