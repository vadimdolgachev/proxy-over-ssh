#ifndef PROXY_OVER_SSH_HTTPCONNECT_H
#define PROXY_OVER_SSH_HTTPCONNECT_H

#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <string_view>

#include "Endpoint.h"

namespace HttpConnect {
    constexpr size_t MaxHeaderSize = 16 * 1024;

    enum class Status {
        ConnectionEstablished,
        BadRequest,
        MethodNotAllowed,
        RequestHeaderFieldsTooLarge,
        HttpVersionNotSupported,
        BadGateway,
    };

    struct Error final {
        Status status;
        std::string message;
    };

    struct Request final {
        Endpoint target;
        size_t headerSize = 0;
    };

    [[nodiscard]] std::expected<Request, Error> parseRequest(std::span<const uint8_t> data);

    [[nodiscard]] std::string_view response(Status status) noexcept;
}

#endif // PROXY_OVER_SSH_HTTPCONNECT_H
