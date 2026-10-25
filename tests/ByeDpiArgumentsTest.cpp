#include <array>
#include <cassert>
#include <cstdlib>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <vector>

#include "ByeDpiRuntime.h"
#include "byedpi/Arguments.h"

// Native conversions used by upstream --oob-data and --fake-data respectively.
extern "C" ssize_t parse_cform(char *buffer, size_t capacity, const char *data, size_t size);
extern "C" char *data_from_str(const char *data, ssize_t *size);

namespace {
    void expectArguments(const std::string_view input, const std::initializer_list<std::string_view> expected) {
        const auto arguments = ByeDpi::Detail::splitArguments(input);
        assert(arguments.front() == "embedded-byedpi");
        assert(arguments.size() == expected.size() + 1);
        std::size_t index = 1;
        for (const auto argument: expected) {
            assert(arguments[index] == argument);
            ++index;
        }
    }

    void expectRejected(const std::string_view input) {
        bool rejected = false;
        try {
            (void) ByeDpi::Detail::splitArguments(input);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        assert(rejected);
    }

    void testNativeBytes() {
        for (const auto input: {R"(--oob-data "\n")", R"(--oob-data '\n')"}) {
            const auto arguments = ByeDpi::Detail::splitArguments(input);
            assert(arguments.size() == 3);
            std::array<char, 1> byte{};
            assert(parse_cform(byte.data(), byte.size(), arguments[2].data(), arguments[2].size()) == 1);
            assert(byte[0] == '\n');
        }
        for (const auto input: {R"(--fake-data ":GET /\r\n\r\n")", R"(--fake-data ':GET /\r\n\r\n')"}) {
            const auto arguments = ByeDpi::Detail::splitArguments(input);
            ssize_t size = 0;
            char *const data = data_from_str(arguments[2].c_str() + 1, &size);
            assert(data != nullptr && size == 9);
            assert(std::string_view(data, static_cast<std::size_t>(size)) == "GET /\r\n\r\n");
            std::free(data);
        }
        const auto arguments = ByeDpi::Detail::splitArguments(R"(--fake-data ":A\x00B")");
        ssize_t size = 0;
        char *const data = data_from_str(arguments[2].c_str() + 1, &size);
        assert(data != nullptr && size == 3);
        assert(std::string_view(data, static_cast<std::size_t>(size)) == std::string_view("A\0B", 3));
        std::free(data);
    }
} // namespace

int main() {
    expectArguments("", {});
    expectArguments(" \t\r\n ", {});
    expectArguments(DefaultByeDpiArgs, {"-f", "-1", "-t", "8", "-S", "-R", "1"});
    expectArguments(R"('one two' "three four" five\ six)", {"one two", "three four", "five six"});
    expectArguments(R"(ab"cd ef"'gh')", {"abcd efgh"});
    expectArguments(R"("" '' a""b'')", {"", "", "ab"});
    expectArguments(R"("\n\r\x41\t\q")", {R"(\n\r\x41\t\q)"});
    expectArguments(R"('a\"b\\c')", {R"(a\"b\\c)"});
    expectArguments(R"("a\"b\\c")", {R"(a"b\c)"});
    expectArguments(R"("\$HOME \`id\`")", {"$HOME `id`"});
    expectArguments(R"args($HOME "$(id)" "*" `id`)args", {"$HOME", "$(id)", "*", "`id`"});
    expectArguments(R"(a\ b \' \" \\)", {"a b", "'", "\"", "\\"});
    expectArguments("--split 1\\\n2", {"--split", "12"});
    expectArguments("\\\n", {});
    expectArguments("\"ab\\\ncd\"", {"abcd"});
    expectArguments("'ab\\\ncd'", {"ab\\\ncd"});
    expectArguments("\"\\\n\"", {""});
    for (const auto input: {"'unterminated", R"("unterminated)", R"(trailing\)", R"("trailing\)", R"("escaped\")"}) {
        expectRejected(input);
    }
    expectRejected(std::string("--oob-data ") + '\0');
    testNativeBytes();
}
