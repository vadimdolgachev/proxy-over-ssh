#include "SshHostKey.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <string>

#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace SshHostKey {
    std::expected<Sha256Digest, std::string> parseSha256Fingerprint(std::string_view fingerprint) {
        while (!fingerprint.empty() && std::isspace(static_cast<unsigned char>(fingerprint.front())) != 0) {
            fingerprint.remove_prefix(1);
        }
        while (!fingerprint.empty() && std::isspace(static_cast<unsigned char>(fingerprint.back())) != 0) {
            fingerprint.remove_suffix(1);
        }
        if (fingerprint.starts_with("SHA256:")) {
            fingerprint.remove_prefix(7);
        }

        if (fingerprint.size() == 43) {
            // OpenSSH omits the single Base64 padding character.
        } else if (fingerprint.size() == 44 && fingerprint.back() == '=') {
            fingerprint.remove_suffix(1);
        } else {
            return std::unexpected("SSH host-key fingerprint must contain a 32-byte SHA-256 digest");
        }

        if (!std::ranges::all_of(fingerprint, [](const char ch) {
                const auto c = static_cast<unsigned char>(ch);
                return std::isalnum(c) != 0 || ch == '+' || ch == '/';
            })) {
            return std::unexpected("SSH host-key fingerprint is not valid Base64");
        }

        const std::string padded = std::string(fingerprint) + '=';
        std::array<Sha256Digest::value_type, 33> decoded{};
        const int decodedSize = EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char *>(padded.data()),
                                                static_cast<int>(padded.size()));
        if (decodedSize != 33) {
            return std::unexpected("SSH host-key fingerprint is not valid Base64");
        }

        Sha256Digest digest{};
        std::ranges::copy_n(decoded.begin(), digest.size(), digest.begin());
        return digest;
    }

    bool matchesSha256(const std::span<const std::uint8_t> hostKey, const Sha256Digest &expected) noexcept {
        Sha256Digest actual{};
        unsigned int digestSize = 0;
        if (EVP_Digest(hostKey.data(), hostKey.size(), actual.data(), &digestSize, EVP_sha256(), nullptr) != 1 ||
            digestSize != actual.size()) {
            return false;
        }
        return CRYPTO_memcmp(actual.data(), expected.data(), expected.size()) == 0;
    }
} // namespace SshHostKey
