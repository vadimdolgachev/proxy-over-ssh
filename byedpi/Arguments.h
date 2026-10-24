#ifndef BYEDPI_ARGUMENTS_H
#define BYEDPI_ARGUMENTS_H

#include <string>
#include <string_view>
#include <vector>

namespace ByeDpi::Detail {
    // Internal argv builder. Performs quoting and escaping without shell expansion.
    [[nodiscard]] std::vector<std::string> splitArguments(std::string_view options);
} // namespace ByeDpi::Detail

#endif // BYEDPI_ARGUMENTS_H
