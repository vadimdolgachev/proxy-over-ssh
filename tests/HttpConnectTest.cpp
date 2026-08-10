#include "HttpConnect.h"

#include <cassert>
#include <string_view>
#include <vector>

namespace {
    [[nodiscard]] std::vector<uint8_t> bytes(const std::string_view text) {
        return {text.begin(), text.end()};
    }

    void expectFailure(const std::string_view request, const HttpConnect::Status status) {
        const auto result = HttpConnect::parseRequest(bytes(request));
        assert(!result.has_value());
        assert(result.error().status == status);
    }
}

int main() {
    {
        const auto request = bytes("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nTLS");
        const auto result = HttpConnect::parseRequest(request);
        assert(result.has_value());
        assert(result->target.host() == "example.com");
        assert(result->target.port() == 443);
        assert(result->headerSize == request.size() - 3);
    }
    {
        const auto result = HttpConnect::parseRequest(bytes(
            "CONNECT 127.0.0.1:8080 HTTP/1.1\r\nhOsT: 127.0.0.1:8080\r\nContent-Length: 0\r\n\r\n"));
        assert(result.has_value());
        assert(result->target.port() == 8080);
    }
    {
        const auto result = HttpConnect::parseRequest(bytes("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert(result.has_value());
        assert(result->target.port() == 8443);
    }

    expectFailure("GET example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n", HttpConnect::Status::MethodNotAllowed);
    expectFailure("CONNECT example.com:443 HTTP/1.0\r\nHost: example.com\r\n\r\n",
        HttpConnect::Status::HttpVersionNotSupported);
    expectFailure("CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n", HttpConnect::Status::BadRequest);
    expectFailure("CONNECT example.com:0 HTTP/1.1\r\nHost: example.com\r\n\r\n", HttpConnect::Status::BadRequest);
    expectFailure("CONNECT example.com:443 HTTP/1.1\r\n\r\n", HttpConnect::Status::BadRequest);
    expectFailure("CONNECT example.com:443 HTTP/1.1\r\nHost: one\r\nHost: two\r\n\r\n",
        HttpConnect::Status::BadRequest);
    expectFailure("CONNECT example.com:443 HTTP/1.1\r\nHost: one\r\n folded\r\n\r\n", HttpConnect::Status::BadRequest);
    expectFailure("CONNECT example.com:443 HTTP/1.1\r\nHost: one\r\nTransfer-Encoding: chunked\r\n\r\n",
        HttpConnect::Status::BadRequest);
    expectFailure("CONNECT example.com:443 HTTP/1.1\r\nHost: one\r\nContent-Length: 1\r\n\r\n",
        HttpConnect::Status::BadRequest);

    std::vector<uint8_t> oversized(HttpConnect::MaxHeaderSize + 1, static_cast<uint8_t>('x'));
    const auto oversizedResult = HttpConnect::parseRequest(oversized);
    assert(!oversizedResult.has_value());
    assert(oversizedResult.error().status == HttpConnect::Status::RequestHeaderFieldsTooLarge);
    return 0;
}
