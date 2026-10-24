#include <cctype>
#include <stdexcept>
#include <utility>

#include "Arguments.h"

namespace ByeDpi::Detail {
    std::vector<std::string> splitArguments(const std::string_view options) {
        if (options.find('\0') != std::string_view::npos) {
            throw std::invalid_argument("ByeDPI arguments contain a NUL byte");
        }
        std::vector<std::string> result{"embedded-byedpi"};
        std::string argument;
        char quote = 0;
        bool started = false;
        for (std::size_t index = 0; index < options.size(); ++index) {
            const char ch = options[index];
            if (quote == '\'') {
                if (ch == '\'') {
                    quote = 0;
                } else {
                    argument += ch;
                }
            } else if (ch == '\\') {
                if (index + 1 == options.size()) {
                    throw std::invalid_argument("Unterminated escape in ByeDPI arguments");
                }
                const char next = options[index + 1];
                if (quote == '"' && next != '"' && next != '\\' && next != '$' && next != '`' && next != '\n') {
                    // ByeDPI itself interprets sequences such as \n, \r and \xNN.
                    argument += ch;
                } else {
                    ++index;
                    if (next != '\n') {
                        argument += next;
                        started = true;
                    }
                }
            } else if (quote == '"') {
                if (ch == '"') {
                    quote = 0;
                } else {
                    argument += ch;
                }
            } else if (ch == '\'' || ch == '"') {
                quote = ch;
                started = true;
            } else if (std::isspace(static_cast<unsigned char>(ch))) {
                if (started) {
                    result.push_back(std::move(argument));
                    argument.clear();
                    started = false;
                }
            } else {
                argument += ch;
                started = true;
            }
        }
        if (quote != 0) {
            throw std::invalid_argument("Unterminated quote in ByeDPI arguments");
        }
        if (started) {
            result.push_back(std::move(argument));
        }
        return result;
    }
} // namespace ByeDpi::Detail
