#ifndef PROXY_OVER_SSH_LOGGER_H
#define PROXY_OVER_SSH_LOGGER_H

#include <iostream>
#include <format>

constexpr bool PRINT_VERBOSE_LOG = true;

template<typename... Args>
void log_d(std::format_string<Args...> fmt, Args &&... args) {
    std::cout << std::format(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
void log_v(std::format_string<Args...> fmt, Args &&... args) {
    if constexpr (PRINT_VERBOSE_LOG) {
        log_d(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
void log_e(std::format_string<Args...> fmt, Args &&... args) {
    std::cerr << std::format(fmt, std::forward<Args>(args)...);
}

#endif //PROXY_OVER_SSH_LOGGER_H
