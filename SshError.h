#ifndef PROXY_OVER_SSH_SSHERROR_H
#define PROXY_OVER_SSH_SSHERROR_H

#include <libssh2.h>
#include <string>

#include "Types.h"
#include "Logger.h"

namespace SshError {
    inline const char *toString(const ResultCode rc) {
        switch (rc) {
            case ResultCode::Ok: return "Ok";
            case ResultCode::ErrAgain: return "ErrAgain";
            case ResultCode::ErrIO: return "ErrIO";
            case ResultCode::ErrTimeout: return "ErrTimeout";
            case ResultCode::ErrInvalidPrivateKey: return "ErrInvalidPrivateKey";
            case ResultCode::ErrUnknown: return "ErrUnknown";
            default: return "Unknown ResultCode";
        }
    }

    inline const char *libSsh2ErrorToString(const int errorCode) {
        switch (errorCode) {
            case LIBSSH2_ERROR_NONE: return "LIBSSH2_ERROR_NONE";
            case LIBSSH2_ERROR_SOCKET_NONE: return "LIBSSH2_ERROR_SOCKET_NONE";
            case LIBSSH2_ERROR_BANNER_RECV: return "LIBSSH2_ERROR_BANNER_RECV";
            case LIBSSH2_ERROR_BANNER_SEND: return "LIBSSH2_ERROR_BANNER_SEND";
            case LIBSSH2_ERROR_INVALID_MAC: return "LIBSSH2_ERROR_INVALID_MAC";
            case LIBSSH2_ERROR_KEX_FAILURE: return "LIBSSH2_ERROR_KEX_FAILURE";
            case LIBSSH2_ERROR_ALLOC: return "LIBSSH2_ERROR_ALLOC";
            case LIBSSH2_ERROR_SOCKET_SEND: return "LIBSSH2_ERROR_SOCKET_SEND";
            case LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE: return "LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE";
            case LIBSSH2_ERROR_TIMEOUT: return "LIBSSH2_ERROR_TIMEOUT";
            case LIBSSH2_ERROR_HOSTKEY_INIT: return "LIBSSH2_ERROR_HOSTKEY_INIT";
            case LIBSSH2_ERROR_HOSTKEY_SIGN: return "LIBSSH2_ERROR_HOSTKEY_SIGN";
            case LIBSSH2_ERROR_DECRYPT: return "LIBSSH2_ERROR_DECRYPT";
            case LIBSSH2_ERROR_SOCKET_DISCONNECT: return "LIBSSH2_ERROR_SOCKET_DISCONNECT";
            case LIBSSH2_ERROR_PROTO: return "LIBSSH2_ERROR_PROTO";
            case LIBSSH2_ERROR_PASSWORD_EXPIRED: return "LIBSSH2_ERROR_PASSWORD_EXPIRED";
            case LIBSSH2_ERROR_FILE: return "LIBSSH2_ERROR_FILE";
            case LIBSSH2_ERROR_METHOD_NONE: return "LIBSSH2_ERROR_METHOD_NONE";
            case LIBSSH2_ERROR_AUTHENTICATION_FAILED: return "LIBSSH2_ERROR_AUTHENTICATION_FAILED";
            case LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED: return "LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED";
            case LIBSSH2_ERROR_CHANNEL_OUTOFORDER: return "LIBSSH2_ERROR_CHANNEL_OUTOFORDER";
            case LIBSSH2_ERROR_CHANNEL_FAILURE: return "LIBSSH2_ERROR_CHANNEL_FAILURE";
            case LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED: return "LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED";
            case LIBSSH2_ERROR_CHANNEL_UNKNOWN: return "LIBSSH2_ERROR_CHANNEL_UNKNOWN";
            case LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED: return "LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED";
            case LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED: return "LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED";
            case LIBSSH2_ERROR_CHANNEL_CLOSED: return "LIBSSH2_ERROR_CHANNEL_CLOSED";
            case LIBSSH2_ERROR_CHANNEL_EOF_SENT: return "LIBSSH2_ERROR_CHANNEL_EOF_SENT";
            case LIBSSH2_ERROR_SCP_PROTOCOL: return "LIBSSH2_ERROR_SCP_PROTOCOL";
            case LIBSSH2_ERROR_ZLIB: return "LIBSSH2_ERROR_ZLIB";
            case LIBSSH2_ERROR_SOCKET_TIMEOUT: return "LIBSSH2_ERROR_SOCKET_TIMEOUT";
            case LIBSSH2_ERROR_SFTP_PROTOCOL: return "LIBSSH2_ERROR_SFTP_PROTOCOL";
            case LIBSSH2_ERROR_REQUEST_DENIED: return "LIBSSH2_ERROR_REQUEST_DENIED";
            case LIBSSH2_ERROR_METHOD_NOT_SUPPORTED: return "LIBSSH2_ERROR_METHOD_NOT_SUPPORTED";
            case LIBSSH2_ERROR_INVAL: return "LIBSSH2_ERROR_INVAL";
            case LIBSSH2_ERROR_INVALID_POLL_TYPE: return "LIBSSH2_ERROR_INVALID_POLL_TYPE";
            case LIBSSH2_ERROR_PUBLICKEY_PROTOCOL: return "LIBSSH2_ERROR_PUBLICKEY_PROTOCOL";
            case LIBSSH2_ERROR_EAGAIN: return "LIBSSH2_ERROR_EAGAIN";
            case LIBSSH2_ERROR_BUFFER_TOO_SMALL: return "LIBSSH2_ERROR_BUFFER_TOO_SMALL";
            case LIBSSH2_ERROR_BAD_USE: return "LIBSSH2_ERROR_BAD_USE";
            case LIBSSH2_ERROR_COMPRESS: return "LIBSSH2_ERROR_COMPRESS";
            case LIBSSH2_ERROR_OUT_OF_BOUNDARY: return "LIBSSH2_ERROR_OUT_OF_BOUNDARY";
            case LIBSSH2_ERROR_AGENT_PROTOCOL: return "LIBSSH2_ERROR_AGENT_PROTOCOL";
            case LIBSSH2_ERROR_SOCKET_RECV: return "LIBSSH2_ERROR_SOCKET_RECV";
            case LIBSSH2_ERROR_ENCRYPT: return "LIBSSH2_ERROR_ENCRYPT";
            case LIBSSH2_ERROR_BAD_SOCKET: return "LIBSSH2_ERROR_BAD_SOCKET";
            case LIBSSH2_ERROR_KNOWN_HOSTS: return "LIBSSH2_ERROR_KNOWN_HOSTS";
            case LIBSSH2_ERROR_CHANNEL_WINDOW_FULL: return "LIBSSH2_ERROR_CHANNEL_WINDOW_FULL";
            default: return "Unknown libssh2 error";
        }
    }

    inline ResultCode libSsh2ToResultCode(const int libSsh2Error) {
        switch (libSsh2Error) {
            case LIBSSH2_ERROR_EAGAIN:
                return ResultCode::ErrAgain;
            case LIBSSH2_ERROR_TIMEOUT:
            case LIBSSH2_ERROR_SOCKET_TIMEOUT:
                return ResultCode::ErrTimeout;
            case LIBSSH2_ERROR_AUTHENTICATION_FAILED:
            case LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED:
                return ResultCode::ErrInvalidPrivateKey;
            case LIBSSH2_ERROR_NONE:
                return ResultCode::Ok;
            default:
                return ResultCode::ErrUnknown;
        }
    }

    inline void logError(const char *operation, int libSsh2Error, const std::string &context = "") {
        if (libSsh2Error == LIBSSH2_ERROR_EAGAIN) {
            return;
        }
        if (context.empty()) {
            log_e("ERROR: {} libssh2 error: {} ({})\n", operation, libSsh2Error, libSsh2ErrorToString(libSsh2Error));
        } else {
            log_e("ERROR: {} libssh2 error: {} ({}), context: {}\n", operation, libSsh2Error,
                  libSsh2ErrorToString(libSsh2Error), context);
        }
    }

    inline void logError(const char *operation,
                         const ResultCode rc,
                         const std::string &context = "") {
        if (rc == ResultCode::ErrAgain) {
            return;
        }
        if (context.empty()) {
            log_e("ERROR: {} result: {}\n", operation, toString(rc));
        } else {
            log_e("ERROR: {} result: {}, context: {}\n", operation, toString(rc), context);
        }
    }
} // namespace SshError

#endif // PROXY_OVER_SSH_SSHERROR_H
