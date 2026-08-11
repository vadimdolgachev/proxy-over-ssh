#include "HttpConnect.h"

#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <cctype>
#include <limits>
#include <netinet/in.h>
#include <system_error>

using namespace CoroLite;

namespace {
    using HttpConnect::Error;
    using HttpConnect::Request;
    using HttpConnect::Status;

    [[nodiscard]] std::expected<Request, Error> fail(const Status status, std::string message) {
        return std::unexpected(Error{status, std::move(message)});
    }

    [[nodiscard]] bool isTokenCharacter(const unsigned char c) noexcept {
        if (std::isalnum(c) != 0) {
            return true;
        }
        constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
        return punctuation.find(static_cast<char>(c)) != std::string_view::npos;
    }

    [[nodiscard]] std::string_view trimOws(std::string_view value) noexcept {
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
            value.remove_prefix(1);
        }
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
            value.remove_suffix(1);
        }
        return value;
    }

    [[nodiscard]] std::string lowercase(const std::string_view value) {
        std::string result(value);
        std::ranges::transform(result, result.begin(), [](const unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return result;
    }

    [[nodiscard]] bool hasInvalidFieldValueCharacter(const std::string_view value) noexcept {
        return std::ranges::any_of(value, [](const unsigned char c) {
            return c == 0x7F || (c < 0x20 && c != '\t');
        });
    }

    [[nodiscard]] std::expected<uint16_t, Error> parsePort(const std::string_view text) {
        unsigned int value = 0;
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
        if (text.empty() || error != std::errc{} || end != text.data() + text.size() || value == 0 ||
            value > std::numeric_limits<uint16_t>::max()) {
            return std::unexpected(Error{Status::BadRequest, "CONNECT authority has an invalid port"});
        }
        return static_cast<uint16_t>(value);
    }

    [[nodiscard]] std::expected<Endpoint, Error> parseAuthority(const std::string_view authority) {
        if (authority.empty()) {
            return std::unexpected(Error{Status::BadRequest, "CONNECT authority is empty"});
        }

        std::string_view host;
        std::string_view portText;
        bool bracketedIpv6 = false;
        if (authority.front() == '[') {
            const size_t close = authority.find(']');
            if (close == std::string_view::npos || close == 1 || close + 1 >= authority.size() ||
                authority[close + 1] != ':') {
                return std::unexpected(Error{Status::BadRequest, "CONNECT IPv6 authority is invalid"});
            }
            host = authority.substr(1, close - 1);
            portText = authority.substr(close + 2);
            bracketedIpv6 = true;
        } else {
            const size_t colon = authority.rfind(':');
            if (colon == std::string_view::npos || colon == 0 || colon + 1 >= authority.size() ||
                authority.find(':') != colon) {
                return std::unexpected(Error{Status::BadRequest, "CONNECT authority must include one explicit port"});
            }
            host = authority.substr(0, colon);
            portText = authority.substr(colon + 1);
        }

        if (std::ranges::any_of(host, [](const unsigned char c) {
                return c <= 0x20 || c == 0x7F || c == '/' || c == '\\' || c == '[' || c == ']';
            })) {
            return std::unexpected(Error{Status::BadRequest, "CONNECT authority has an invalid host"});
        }

        const auto port = parsePort(portText);
        if (!port) {
            return std::unexpected(port.error());
        }

        if (bracketedIpv6) {
            sockaddr_in6 address{};
            address.sin6_family = AF_INET6;
            address.sin6_port = htons(*port);
            const std::string hostString(host);
            if (inet_pton(AF_INET6, hostString.c_str(), &address.sin6_addr) != 1) {
                return std::unexpected(Error{Status::BadRequest, "CONNECT IPv6 address is invalid"});
            }
            return Endpoint(address);
        }

        sockaddr_in address{};
        const std::string hostString(host);
        if (inet_pton(AF_INET, hostString.c_str(), &address.sin_addr) == 1) {
            address.sin_family = AF_INET;
            address.sin_port = htons(*port);
            return Endpoint(address);
        }
        return Endpoint(hostString, *port);
    }
}

std::expected<Request, Error> HttpConnect::parseRequest(const std::span<const uint8_t> data) {
    if (data.size() > MaxHeaderSize) {
        return fail(Status::RequestHeaderFieldsTooLarge, "HTTP request headers exceed 16 KiB");
    }

    const std::string_view text(reinterpret_cast<const char *>(data.data()), data.size());
    const size_t headerEnd = text.find("\r\n\r\n");
    if (headerEnd == std::string_view::npos) {
        return fail(Status::BadRequest, "HTTP request headers are incomplete");
    }

    const size_t requestLineEnd = text.find("\r\n");
    if (requestLineEnd == std::string_view::npos || requestLineEnd == 0) {
        return fail(Status::BadRequest, "HTTP request line is invalid");
    }
    const std::string_view requestLine = text.substr(0, requestLineEnd);
    const size_t firstSpace = requestLine.find(' ');
    const size_t secondSpace = firstSpace == std::string_view::npos ? firstSpace : requestLine.find(' ', firstSpace + 1);
    if (firstSpace == std::string_view::npos || secondSpace == std::string_view::npos || firstSpace == 0 ||
        secondSpace == firstSpace + 1 || requestLine.find(' ', secondSpace + 1) != std::string_view::npos) {
        return fail(Status::BadRequest, "HTTP request line must contain method, authority, and version");
    }

    const std::string_view method = requestLine.substr(0, firstSpace);
    const std::string_view authority = requestLine.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    const std::string_view version = requestLine.substr(secondSpace + 1);
    if (method != "CONNECT") {
        return fail(Status::MethodNotAllowed, "Only the CONNECT method is supported");
    }
    if (version != "HTTP/1.1") {
        return fail(Status::HttpVersionNotSupported, "Only HTTP/1.1 is supported");
    }

    const auto target = parseAuthority(authority);
    if (!target) {
        return std::unexpected(target.error());
    }

    size_t hostCount = 0;
    bool contentLengthSeen = false;
    size_t position = requestLineEnd + 2;
    while (position < headerEnd) {
        const size_t lineEnd = text.find("\r\n", position);
        if (lineEnd == std::string_view::npos || lineEnd > headerEnd || lineEnd == position) {
            return fail(Status::BadRequest, "HTTP header line is invalid");
        }
        const std::string_view line = text.substr(position, lineEnd - position);
        if (line.front() == ' ' || line.front() == '\t') {
            return fail(Status::BadRequest, "Obsolete folded HTTP headers are not supported");
        }
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0 ||
            !std::ranges::all_of(line.substr(0, colon), isTokenCharacter)) {
            return fail(Status::BadRequest, "HTTP header name is invalid");
        }
        const std::string_view value = trimOws(line.substr(colon + 1));
        if (hasInvalidFieldValueCharacter(value)) {
            return fail(Status::BadRequest, "HTTP header value contains a control character");
        }

        if (const auto name = lowercase(line.substr(0, colon)); name == "host") {
            ++hostCount;
            if (value.empty()) {
                return fail(Status::BadRequest, "Host header must not be empty");
            }
        } else if (name == "transfer-encoding") {
            return fail(Status::BadRequest, "Transfer-Encoding is not valid on CONNECT requests");
        } else if (name == "content-length") {
            if (contentLengthSeen || value != "0") {
                return fail(Status::BadRequest, "CONNECT Content-Length must occur once and equal zero");
            }
            contentLengthSeen = true;
        }
        position = lineEnd + 2;
    }

    if (hostCount != 1) {
        return fail(Status::BadRequest, "HTTP/1.1 CONNECT requires exactly one Host header");
    }
    return Request{.target = *target, .headerSize = headerEnd + 4};
}

std::string_view HttpConnect::response(const Status status) noexcept {
    switch (status) {
        case Status::ConnectionEstablished:
            return "HTTP/1.1 200 Connection Established\r\n\r\n";
        case Status::BadRequest:
            return "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        case Status::MethodNotAllowed:
            return "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        case Status::RequestHeaderFieldsTooLarge:
            return "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        case Status::HttpVersionNotSupported:
            return "HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        case Status::BadGateway:
            return "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    }
    return {};
}
