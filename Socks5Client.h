#ifndef SOCKS5_CLIENT_H
#define SOCKS5_CLIENT_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "Endpoint.h"
#include "Types.h"

// Incremental SOCKS5 CONNECT. Reads exactly the reply, preserving any following SSH bytes.
class Socks5Client final {
public:
    explicit Socks5Client(const CoroLite::Endpoint &destination);

    [[nodiscard]] ResultCode advance(int fd);
    [[nodiscard]] bool wantsRead() const noexcept;
    [[nodiscard]] const std::string &error() const noexcept;

private:
    enum class State { Greeting, Method, Connect, Header, DomainLength, Address, Done, Failed };

    ResultCode transfer(int fd, bool reading);
    ResultCode fail(std::string message);

    State state = State::Greeting;
    std::vector<std::uint8_t> request;
    std::array<std::uint8_t, 257> reply{};
    std::size_t offset = 0;
    std::size_t expected = 3;
    std::string errorMessage;
};

#endif // SOCKS5_CLIENT_H
