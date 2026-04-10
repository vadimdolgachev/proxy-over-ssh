#ifndef PROXY_OVER_SSH_SSHCONSTATEMACHINE_H
#define PROXY_OVER_SSH_SSHCONSTATEMACHINE_H

#include "Types.h"

class SshConStateMachine final {
public:
    enum class State {
        DISCONNECTED,
        TCP_CONNECTED,
        SSH_HANDSHAKE,
        SSH_AUTHENTICATED,
        CHANNEL_CREATED,
        ERROR
    };

    class Context {
    public:
        virtual ~Context() = default;

        virtual ResultCode tryTcpConnect() = 0;

        virtual ResultCode performHandshake() = 0;

        virtual ResultCode performAuthentication() = 0;

        virtual ResultCode createChannel() = 0;
    };

    SshConStateMachine() = default;

    [[nodiscard]] State getState() const noexcept;

    void setState(State newState) noexcept;

    [[nodiscard]] bool isTerminal() const noexcept;

    ResultCode advance(Context &context, int *pendingDirections);

private:
    State state = State::DISCONNECTED;
};

#endif // SSHCONSTATEMACHINE_H
