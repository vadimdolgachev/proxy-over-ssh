#include <arpa/inet.h>
#include <array>
#include <cassert>
#include <cstdint>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "Socks5Client.h"

using namespace CoroLite;

namespace {
    Endpoint ipEndpoint(const char *host) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(22);
        if (inet_pton(AF_INET, host, &address.sin_addr) == 1)
            return Endpoint(address);
        sockaddr_in6 address6{};
        address6.sin6_family = AF_INET6;
        address6.sin6_port = htons(22);
        assert(inet_pton(AF_INET6, host, &address6.sin6_addr) == 1);
        return Endpoint(address6);
    }
    struct SocketPair {
        int fds[2]{};
        SocketPair() {
            assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds) == 0);
        }
        ~SocketPair() {
            close(fds[0]);
            close(fds[1]);
        }
    };

    void sendBytes(int fd, const std::vector<std::uint8_t> &bytes) {
        assert(send(fd, bytes.data(), bytes.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(bytes.size()));
    }

    void authenticate(Socks5Client &client, const SocketPair &pair) {
        assert(client.advance(pair.fds[0]) == ResultCode::ErrAgain);
        std::array<std::uint8_t, 3> greeting{};
        assert(recv(pair.fds[1], greeting.data(), greeting.size(), 0) == 3);
        assert((greeting == std::array<std::uint8_t, 3>{5, 1, 0}));
        sendBytes(pair.fds[1], {5});
        assert(client.advance(pair.fds[0]) == ResultCode::ErrAgain);
        sendBytes(pair.fds[1], {0});
        assert(client.advance(pair.fds[0]) == ResultCode::ErrAgain);
    }

    void testConnect(const Endpoint &endpoint,
                     const std::vector<std::uint8_t> &expectedRequest,
                     const std::vector<std::uint8_t> &reply) {
        SocketPair pair;
        Socks5Client client(endpoint);
        authenticate(client, pair);
        std::array<std::uint8_t, 300> request{};
        const auto size = recv(pair.fds[1], request.data(), request.size(), 0);
        assert(size == static_cast<ssize_t>(expectedRequest.size()));
        assert(std::vector(request.begin(), request.begin() + size) == expectedRequest);
        // Deliver every part of the SOCKS5 response separately.
        for (std::size_t i = 0; i + 1 < reply.size(); ++i) {
            sendBytes(pair.fds[1], {reply[i]});
            assert(client.advance(pair.fds[0]) == ResultCode::ErrAgain);
            assert(client.wantsRead());
        }
        const std::string banner = "SSH-2.0-test\r\n";
        std::vector<std::uint8_t> last{reply.back()};
        last.insert(last.end(), banner.begin(), banner.end());
        sendBytes(pair.fds[1], last);
        assert(client.advance(pair.fds[0]) == ResultCode::Ok);
        assert(client.advance(pair.fds[0]) == ResultCode::Ok);
        std::array<char, 100> remaining{};
        const auto count = recv(pair.fds[0], remaining.data(), remaining.size(), 0);
        assert(count == static_cast<ssize_t>(banner.size()));
        assert(std::string(remaining.data(), static_cast<std::size_t>(count)) == banner);
    }

    void testInvalidMethod() {
        for (const auto &method: {std::vector<std::uint8_t>{5, 255}, std::vector<std::uint8_t>{4, 0}}) {
            SocketPair pair;
            Socks5Client client(Endpoint("127.0.0.1", 22));
            assert(client.advance(pair.fds[0]) == ResultCode::ErrAgain);
            sendBytes(pair.fds[1], method);
            assert(client.advance(pair.fds[0]) == ResultCode::ErrIO);
            assert(!client.error().empty());
        }
    }

    void testRejectedReply(const std::vector<std::uint8_t> &reply) {
        SocketPair pair;
        Socks5Client client(Endpoint("127.0.0.1", 22));
        authenticate(client, pair);
        sendBytes(pair.fds[1], reply);
        assert(client.advance(pair.fds[0]) == ResultCode::ErrIO);
        assert(!client.error().empty());
    }
} // namespace

int main() {
    testConnect(ipEndpoint("127.0.0.1"), {5, 1, 0, 1, 127, 0, 0, 1, 0, 22}, {5, 0, 0, 1, 127, 0, 0, 1, 0, 22});
    std::vector<std::uint8_t> ipv6Request{5, 1, 0, 4};
    ipv6Request.insert(ipv6Request.end(), 15, 0);
    ipv6Request.insert(ipv6Request.end(), {1, 0, 22});
    std::vector<std::uint8_t> ipv6Reply = ipv6Request;
    ipv6Reply[1] = 0;
    testConnect(ipEndpoint("::1"), ipv6Request, ipv6Reply);
    testConnect(Endpoint("ssh.test", 2222), {5, 1, 0, 3, 8, 's', 's', 'h', '.', 't', 'e', 's', 't', 8, 174},
                {5, 0, 0, 3, 3, 'f', 'o', 'o', 0, 22});
    testInvalidMethod();
    testRejectedReply({5, 5, 0, 1});
    testRejectedReply({4, 0, 0, 1});
    testRejectedReply({5, 0, 1, 1});
    testRejectedReply({5, 0, 0, 2});
    testRejectedReply({5, 0, 0, 3, 0});
    SocketPair pair;
    Socks5Client client(Endpoint("127.0.0.1", 22));
    assert(client.advance(pair.fds[0]) == ResultCode::ErrAgain);
    assert(shutdown(pair.fds[1], SHUT_RDWR) == 0);
    assert(client.advance(pair.fds[0]) == ResultCode::ErrIO);
}
