#include <array>
#include <cassert>
#include <string>

#include "SshHostKey.h"

int main() {
    // SHA-256("abc") in OpenSSH fingerprint form.
    constexpr auto fingerprint = "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0";
    const auto parsed = SshHostKey::parseSha256Fingerprint(fingerprint);
    assert(parsed.has_value());
    assert(SshHostKey::matchesSha256(std::span{reinterpret_cast<const std::uint8_t *>("abc"), 3}, *parsed));

    assert(SshHostKey::parseSha256Fingerprint(std::string(fingerprint) + "=").has_value());
    assert(!SshHostKey::parseSha256Fingerprint("SHA256:invalid").has_value());
    assert(!SshHostKey::parseSha256Fingerprint("SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa!").has_value());

    const std::array<std::uint8_t, 3> different{'a', 'b', 'd'};
    assert(!SshHostKey::matchesSha256(different, *parsed));
}
