//
// Created by vadim on 19.03.2026.
//

#ifndef PROXY_OVER_SSH_TYPES_H
#define PROXY_OVER_SSH_TYPES_H

// Result codes for async operations
enum class ResultCode {
    Ok,
    ErrAgain,
    ErrIO,
    ErrTimeout,
    ErrInvalidPrivateKey,
    ErrUnknown,
};

namespace Socks5 {
    constexpr int Version = 0x5;

    namespace Cmd {
        constexpr int Connect = 0x1;
    }

    namespace Auth {
        constexpr int NoAuth = 0x0;
    }

    namespace Atyp {
        constexpr int IpV4 = 0x1;
        constexpr int Domain = 0x3;
        constexpr int IpV6 = 0x4;
    }

    namespace Rep {
        constexpr int Success = 0x00;
        constexpr int GeneralFailure = 0x01;
        constexpr int ConnectionNotAllowed = 0x02;
        constexpr int NetworkUnreachable = 0x03;
        constexpr int HostUnreachable = 0x04;
        constexpr int ConnectionRefused = 0x05;
        constexpr int TtlExpired = 0x06;
        constexpr int CommandNotSupported = 0x07;
        constexpr int AddressTypeNotSupported = 0x08;
    }
} // namespace Socks5

#endif //PROXY_OVER_SSH_TYPES_H
