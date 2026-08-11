#ifndef PROXY_OVER_SSH_SSHHOSTKEY_H
#define PROXY_OVER_SSH_SSHHOSTKEY_H

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace SshHostKey {
    using Sha256Digest = std::array<std::uint8_t, 32>;

    [[nodiscard]] std::expected<Sha256Digest, std::string> parseSha256Fingerprint(std::string_view fingerprint);

    [[nodiscard]] bool matchesSha256(std::span<const std::uint8_t> hostKey, const Sha256Digest &expected) noexcept;
} // namespace SshHostKey

#endif // PROXY_OVER_SSH_SSHHOSTKEY_H
