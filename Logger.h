#ifndef PROXY_OVER_SSH_LOGGER_H
#define PROXY_OVER_SSH_LOGGER_H

#include <iostream>
#include <format>
#include <sstream>
#include <thread>

constexpr bool PRINT_VERBOSE_LOG = true;

inline std::string threadId() {
    std::ostringstream os;
    os << std::this_thread::get_id();
    return os.str();
}

template<typename... Args>
void log_d(std::format_string<Args...> fmt, Args &&... args) {
    std::cout << std::format("[{}] {}", threadId(), std::format(fmt, std::forward<Args>(args)...));
}

template<typename... Args>
void log_v(std::format_string<Args...> fmt, Args &&... args) {
    if constexpr (PRINT_VERBOSE_LOG) {
        log_d(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
void log_e(std::format_string<Args...> fmt, Args &&... args) {
    std::cerr << std::format("[{}] {}", threadId(), std::format(fmt, std::forward<Args>(args)...));
}

#endif //PROXY_OVER_SSH_LOGGER_H
