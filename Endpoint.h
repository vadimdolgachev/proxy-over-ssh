//
// Created by vadim on 29.01.2026.
//

#ifndef PROXY_OVER_SSH_ENDPOINT_H
#define PROXY_OVER_SSH_ENDPOINT_H

#include <cstddef>
#include <cstring>
#include <netinet/in.h>
#include <functional>
#include <string>
#include <variant>

class Endpoint final {
public:
    enum class Type {
        IPv4,
        IPv6,
        Hostname
    };

    Endpoint() = default;

    explicit Endpoint(const sockaddr_in &addr_);

    explicit Endpoint(const sockaddr_in6 &addr6_);

    explicit Endpoint(uint16_t port);

    Endpoint(const std::string &host, uint16_t port);

    Endpoint(const sockaddr_storage &storage, socklen_t len);

    [[nodiscard]] Type type() const noexcept;

    [[nodiscard]] uint16_t port() const;

    [[nodiscard]] uint32_t ip() const;

    [[nodiscard]] std::string ipStr() const;

    [[nodiscard]] std::string toString() const;

    [[nodiscard]] std::string host() const;

    [[nodiscard]] bool isIP() const noexcept;

    [[nodiscard]] bool isIPv4() const noexcept;

    [[nodiscard]] bool isIPv6() const noexcept;

    [[nodiscard]] bool isHostname() const noexcept;

    [[nodiscard]] const sockaddr_in &sockaddr() const;

    [[nodiscard]] const sockaddr_in6 &sockaddr6() const;

    [[nodiscard]] std::pair<sockaddr_storage, socklen_t> sockaddrStorage() const;

private:
    struct IPv4Addr {
        sockaddr_in addr{};
    };

    struct IPv6Addr {
        sockaddr_in6 addr{};
    };

    struct HostnameAddr {
        std::string host;
        uint16_t port;
    };

    std::variant<IPv4Addr, IPv6Addr, HostnameAddr> storage{IPv4Addr{}};

    friend bool operator==(const Endpoint &lhs, const Endpoint &rhs) noexcept;

    friend struct std::hash<Endpoint>;
};

template<>
struct std::hash<Endpoint> {
    size_t operator()(const Endpoint &endpoint) const noexcept;
};

inline bool operator==(const Endpoint &lhs, const Endpoint &rhs) noexcept {
    if (lhs.type() != rhs.type()) {
        return false;
    }

    if (lhs.port() != rhs.port()) {
        return false;
    }

    if (lhs.isIPv4()) {
        const auto &lhsAddr = std::get<Endpoint::IPv4Addr>(lhs.storage);
        const auto &rhsAddr = std::get<Endpoint::IPv4Addr>(rhs.storage);
        return lhsAddr.addr.sin_addr.s_addr == rhsAddr.addr.sin_addr.s_addr;
    }

    if (lhs.isIPv6()) {
        const auto &lhsAddr = std::get<Endpoint::IPv6Addr>(lhs.storage);
        const auto &rhsAddr = std::get<Endpoint::IPv6Addr>(rhs.storage);
        return memcmp(&lhsAddr.addr.sin6_addr, &rhsAddr.addr.sin6_addr, sizeof(in6_addr)) == 0;
    }

    if (lhs.isHostname()) {
        const auto &lhsAddr = std::get<Endpoint::HostnameAddr>(lhs.storage);
        const auto &rhsAddr = std::get<Endpoint::HostnameAddr>(rhs.storage);
        return lhsAddr.host == rhsAddr.host;
    }

    return false;
}

#endif //PROXY_OVER_SSH_ENDPOINT_H
