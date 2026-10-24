#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <sys/socket.h>
#include <utility>

#include "Socks5Client.h"

using namespace CoroLite;

namespace {
    constexpr std::array<std::uint8_t, 3> Greeting{5, 1, 0};
}

Socks5Client::Socks5Client(const Endpoint &destination) :
    request{5, 1, 0} {
    if (destination.isIPv4()) {
        request.push_back(1);
        const auto *address = reinterpret_cast<const std::uint8_t *>(&destination.sockaddr().sin_addr);
        request.insert(request.end(), address, address + sizeof(in_addr));
    } else if (destination.isIPv6()) {
        request.push_back(4);
        const auto *address = reinterpret_cast<const std::uint8_t *>(&destination.sockaddr6().sin6_addr);
        request.insert(request.end(), address, address + sizeof(in6_addr));
    } else {
        const auto host = destination.host();
        if (host.empty() || host.size() > 255) {
            throw std::invalid_argument("Invalid SOCKS5 destination hostname");
        }
        request.push_back(3);
        request.push_back(static_cast<std::uint8_t>(host.size()));
        request.insert(request.end(), host.begin(), host.end());
    }
    request.push_back(static_cast<std::uint8_t>(destination.port() >> 8));
    request.push_back(static_cast<std::uint8_t>(destination.port() & 0xff));
}

ResultCode Socks5Client::fail(std::string message) {
    state = State::Failed;
    errorMessage = std::move(message);
    return ResultCode::ErrIO;
}

ResultCode Socks5Client::transfer(const int fd, const bool reading) {
    while (offset < expected) {
        const auto *data = state == State::Greeting ? Greeting.data() : request.data();
        const auto count = reading ? recv(fd, reply.data() + offset, expected - offset, 0)
                                   : send(fd, data + offset, expected - offset, MSG_NOSIGNAL);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return ResultCode::ErrAgain;
        } else {
            return fail(count == 0 ? "SOCKS5 connection closed during CONNECT"
                                   : std::string("SOCKS5 I/O failed: ") + std::strerror(errno));
        }
    }
    offset = 0;
    return ResultCode::Ok;
}

ResultCode Socks5Client::advance(const int fd) {
    while (state != State::Done && state != State::Failed) {
        if (const auto result = transfer(fd, wantsRead()); result != ResultCode::Ok) {
            return result;
        }
        switch (state) {
            case State::Greeting:
                state = State::Method;
                expected = 2;
                break;
            case State::Method:
                if (reply[0] != 5 || reply[1] != 0) {
                    return fail("SOCKS5 proxy rejected unauthenticated access");
                }
                state = State::Connect;
                expected = request.size();
                break;
            case State::Connect:
                state = State::Header;
                expected = 4;
                break;
            case State::Header:
                if (reply[0] != 5 || reply[1] != 0 || reply[2] != 0) {
                    return fail("SOCKS5 CONNECT rejected, reply code " + std::to_string(reply[1]));
                }
                if (reply[3] == 1 || reply[3] == 4) {
                    state = State::Address;
                    expected = reply[3] == 1 ? 6 : 18;
                } else if (reply[3] == 3) {
                    state = State::DomainLength;
                    expected = 1;
                } else {
                    return fail("SOCKS5 proxy returned an invalid address type");
                }
                break;
            case State::DomainLength:
                if (reply[0] == 0) {
                    return fail("SOCKS5 proxy returned an empty bound hostname");
                }
                state = State::Address;
                expected = static_cast<std::size_t>(reply[0]) + 2;
                break;
            case State::Address:
                state = State::Done;
                break;
            case State::Done:
            case State::Failed:
                break;
        }
    }
    return state == State::Done ? ResultCode::Ok : ResultCode::ErrIO;
}

bool Socks5Client::wantsRead() const noexcept {
    return state == State::Method || state == State::Header || state == State::DomainLength || state == State::Address;
}

const std::string &Socks5Client::error() const noexcept {
    return errorMessage;
}
