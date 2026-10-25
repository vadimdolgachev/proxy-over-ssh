#ifndef BYE_DPI_RUNTIME_H
#define BYE_DPI_RUNTIME_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

struct byedpi_engine;

#if defined(__ANDROID__)
inline constexpr std::string_view DefaultByeDpiArgs = "-f -1 -t 8 -R 1";
#else
inline constexpr std::string_view DefaultByeDpiArgs = "-f -1 -t 8 -S -R 1";
#endif

class ByeDpiRuntime final {
public:
    using SocketProtector = std::function<bool(int)>;
    using FailureCallback = std::function<void(int)>;

    explicit ByeDpiRuntime(std::string_view options, SocketProtector protector = {}, FailureCallback onFailure = {});
    ~ByeDpiRuntime();

    ByeDpiRuntime(const ByeDpiRuntime &) = delete;
    ByeDpiRuntime &operator=(const ByeDpiRuntime &) = delete;

    [[nodiscard]] std::uint16_t port() const noexcept;
    [[nodiscard]] bool isRunning() const noexcept;
    // Safe from the failure callback; destruction/join must happen on the owning thread.
    void requestStop() noexcept;

private:
    static int protectSocket(int fd, void *context) noexcept;

    SocketProtector socketProtector;
    FailureCallback failureCallback;
    std::vector<std::string> arguments;
    std::vector<char *> argumentPointers;
    byedpi_engine *engine = nullptr;
    std::atomic_bool running = false;
    std::atomic_bool stopping = false;
    std::thread worker;
};

#endif // BYE_DPI_RUNTIME_H
