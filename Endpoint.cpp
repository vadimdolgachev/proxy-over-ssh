//
// Created by vadim on 29.01.2026.
//

#include "Endpoint.h"

#include <iostream>
#include <ostream>
#include <arpa/inet.h>
#include <stdexcept>
#include <cstring>
#include <array>
#include <utility>

Endpoint::Endpoint(const sockaddr_in &addr_) {
    storage = IPv4Addr{addr_};
}

Endpoint::Endpoint(const sockaddr_in6 &addr6_) {
    storage = IPv6Addr{addr6_};
}

Endpoint::Endpoint(const uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    storage = IPv4Addr{addr};
}

Endpoint::Endpoint(const std::string &host, uint16_t port) {
    storage = HostnameAddr{host, port};
}

Endpoint::Endpoint(const sockaddr_storage &storage_, socklen_t len) {
    if (len >= sizeof(sockaddr_in6) && storage_.ss_family == AF_INET6) {
        sockaddr_in6 addr6{};
        std::memcpy(&addr6, &storage_, sizeof(sockaddr_in6));
        this->storage = IPv6Addr{addr6};
    } else if (len >= sizeof(sockaddr_in) && storage_.ss_family == AF_INET) {
        sockaddr_in addr{};
        std::memcpy(&addr, &storage_, sizeof(sockaddr_in));
        this->storage = IPv4Addr{addr};
    } else {
        throw std::runtime_error("Invalid sockaddr_storage or length");
    }
}

Endpoint::Type Endpoint::type() const noexcept {
    return std::visit([](const auto &addr) {
        using T = std::decay_t<decltype(addr)>;
        if constexpr (std::is_same_v<T, IPv4Addr>) {
            return Type::IPv4;
        } else if constexpr (std::is_same_v<T, IPv6Addr>) {
            return Type::IPv6;
        } else if constexpr (std::is_same_v<T, HostnameAddr>) {
            return Type::Hostname;
        }
    }, storage);
}

uint16_t Endpoint::port() const {
    return std::visit([](const auto &addr) -> uint16_t {
        using T = std::decay_t<decltype(addr)>;
        if constexpr (std::is_same_v<T, IPv4Addr>) {
            return ntohs(addr.addr.sin_port);
        } else if constexpr (std::is_same_v<T, IPv6Addr>) {
            return ntohs(addr.addr.sin6_port);
        } else if constexpr (std::is_same_v<T, HostnameAddr>) {
            return addr.port;
        }
    }, storage);
}

uint32_t Endpoint::ip() const {
    if (!isIPv4()) {
        throw std::runtime_error("Endpoint::ip() called on non-IPv4 endpoint");
    }
    const auto &ipv4 = std::get<IPv4Addr>(storage);
    return ntohl(ipv4.addr.sin_addr.s_addr);
}

std::string Endpoint::ipStr() const {
    if (!isIP()) {
        throw std::runtime_error("Endpoint::ipStr() called on non-IP endpoint");
    }

    if (isIPv4()) {
        const auto &ipv4 = std::get<IPv4Addr>(storage);
        std::array<char, INET_ADDRSTRLEN> ipStr = {};
        inet_ntop(AF_INET, &ipv4.addr.sin_addr, ipStr.data(), INET_ADDRSTRLEN);
        return {ipStr.data()};
    } else {
        const auto &ipv6 = std::get<IPv6Addr>(storage);
        std::array<char, INET6_ADDRSTRLEN> ipStr = {};
        inet_ntop(AF_INET6, &ipv6.addr.sin6_addr, ipStr.data(), INET6_ADDRSTRLEN);
        return {ipStr.data()};
    }
}

std::string Endpoint::toString() const {
    if (isIP()) {
        return ipStr() + ":" + std::to_string(port());
    } else {
        const auto &hostname = std::get<HostnameAddr>(storage);
        return hostname.host + ":" + std::to_string(hostname.port);
    }
}

std::string Endpoint::host() const {
    if (isIP()) {
        return ipStr();
    } else {
        const auto &hostname = std::get<HostnameAddr>(storage);
        return hostname.host;
    }
}

bool Endpoint::isIP() const noexcept {
    return isIPv4() || isIPv6();
}

bool Endpoint::isIPv4() const noexcept {
    return std::holds_alternative<IPv4Addr>(storage);
}

bool Endpoint::isIPv6() const noexcept {
    return std::holds_alternative<IPv6Addr>(storage);
}

bool Endpoint::isHostname() const noexcept {
    return std::holds_alternative<HostnameAddr>(storage);
}

const sockaddr_in &Endpoint::sockaddr() const {
    if (!isIPv4()) {
        throw std::runtime_error("Endpoint::sockaddr() called on non-IPv4 endpoint");
    }
    return std::get<IPv4Addr>(storage).addr;
}

const sockaddr_in6 &Endpoint::sockaddr6() const {
    if (!isIPv6()) {
        throw std::runtime_error("Endpoint::sockaddr6() called on non-IPv6 endpoint");
    }
    return std::get<IPv6Addr>(storage).addr;
}

std::pair<sockaddr_storage, socklen_t> Endpoint::sockaddrStorage() const {
    sockaddr_storage storage_{};
    socklen_t len = 0;

    if (isIPv4()) {
        const auto &[addr] = std::get<IPv4Addr>(this->storage);
        std::memcpy(&storage_, &addr, sizeof(sockaddr_in));
        len = sizeof(sockaddr_in);
    } else if (isIPv6()) {
        const auto &[addr] = std::get<IPv6Addr>(this->storage);
        std::memcpy(&storage_, &addr, sizeof(sockaddr_in6));
        len = sizeof(sockaddr_in6);
    } else {
        throw std::runtime_error("Endpoint::sockaddrStorage() called on non-IP endpoint");
    }

    return {storage_, len};
}

size_t std::hash<Endpoint>::operator()(const Endpoint &endpoint) const noexcept {
    std::hash<uint16_t> portHasher;
    std::hash<int> typeHasher;
    std::hash<uint32_t> ip4Hasher;
    std::hash<uint64_t> ip6Hasher;
    std::hash<std::string> stringHasher;

    const size_t portHash = portHasher(endpoint.port());
    const size_t typeHash = typeHasher(static_cast<int>(endpoint.type()));

    if (endpoint.isIPv4()) {
        const auto &ipv4 = std::get<Endpoint::IPv4Addr>(endpoint.storage);
        const uint32_t ip = ntohl(ipv4.addr.sin_addr.s_addr);
        return portHash ^ typeHash ^ ip4Hasher(ip);
    }
    if (endpoint.isIPv6()) {
        const auto &ipv6 = std::get<Endpoint::IPv6Addr>(endpoint.storage);
        const auto *ip6Parts = reinterpret_cast<const uint64_t *>(&ipv6.addr.sin6_addr);
        return portHash ^ typeHash ^ ip6Hasher(ip6Parts[0]) ^ ip6Hasher(ip6Parts[1]);
    }
    if (endpoint.isHostname()) {
        const auto &hostname = std::get<Endpoint::HostnameAddr>(endpoint.storage);
        return portHash ^ typeHash ^ stringHasher(hostname.host);
    }

    return portHash ^ typeHash;
}
