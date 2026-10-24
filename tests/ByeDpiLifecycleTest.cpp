#include <atomic>
#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "ByeDpiRuntime.h"

namespace {
    std::atomic_int nextAcceptError = 0;
    std::atomic_int nextPollError = 0;

    template<class Predicate> void waitUntil(Predicate predicate) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!predicate() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        assert(predicate());
    }

    int connectLocal(const std::uint16_t port) {
        const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert(fd >= 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        assert(connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
        return fd;
    }

    class TemporaryDirectory {
    public:
        TemporaryDirectory() {
            char pattern[] = "/tmp/byedpi-lifecycle-XXXXXX";
            const auto *directory = mkdtemp(pattern);
            assert(directory);
            path = directory;
        }
        ~TemporaryDirectory() { std::filesystem::remove_all(path); }
        std::filesystem::path path;
    };

    std::string readFile(const std::filesystem::path &path) {
        std::ifstream input(path);
        return {std::istreambuf_iterator(input), std::istreambuf_iterator<char>()};
    }

    void testFatal(bool pollFailure, bool throwingCallback) {
        std::atomic_int calls = 0;
        std::atomic_int error = 0;
        const TemporaryDirectory directory;
        const auto cache = directory.path / "cache";
        {
            ByeDpiRuntime runtime("--cache-file " + cache.string(), {}, [&](const int code) {
                error.store(code);
                ++calls;
                if (throwingCallback) throw std::runtime_error("test callback failure");
            });
            if (pollFailure) nextPollError.store(EIO);
            else nextAcceptError.store(EMFILE);
            const int client = connectLocal(runtime.port());
            waitUntil([&] { return calls.load() == 1; });
            assert(!runtime.isRunning());
            assert(error.load() == (pollFailure ? EIO : EMFILE));
            close(client);
        }
        assert(calls == 1 && std::filesystem::exists(cache));
        ByeDpiRuntime retry("--split 2");
        assert(retry.isRunning());
    }

    void testStartupFailureDoesNotOverwriteCache() {
        const TemporaryDirectory directory;
        const auto cache = directory.path / "cache";
        const std::string original = "0 127.0.0.1 32 22 1 -\n";
        std::ofstream(cache) << original;
        try {
            ByeDpiRuntime runtime("--cache-file " + cache.string() + " --not-an-option");
            assert(false);
        } catch (const std::runtime_error &) {
        }
        assert(readFile(cache) == original);
    }

    void testPersistence() {
        const TemporaryDirectory directory;
        const auto first = directory.path / "first";
        const auto second = directory.path / "second";
        std::ofstream(first) << "0 127.0.0.1 32 22 1 fixture.example\ninvalid\n";
        std::atomic_int failures = 0;
        {
            ByeDpiRuntime runtime("-y " + first.string() + " -A none -y " + second.string(), {},
                                  [&](int) { ++failures; });
            runtime.requestStop();
            runtime.requestStop();
            waitUntil([&] { return !runtime.isRunning(); });
        }
        assert(failures == 0);
        assert(readFile(first) == "0 127.0.0.1 32 22 1 fixture.example\n");
        assert(std::filesystem::exists(second));
        // Verify that a saved cache can be loaded and saved by the next instance.
        {
            ByeDpiRuntime runtime("-y " + first.string());
        }
        assert(readFile(first) == "0 127.0.0.1 32 22 1 fixture.example\n");
        {
            ByeDpiRuntime runtime("-y " + (directory.path / "missing/cache").string() +
                                  " -A none -y " + second.string(), {}, [&](int) { ++failures; });
        }
        assert(failures == 0 && std::filesystem::exists(second));
        // Force an actual write/flush failure after loading a valid, nonempty cache.
        {
            ByeDpiRuntime runtime("-y " + first.string(), {}, [&](int) { ++failures; });
            std::filesystem::remove(first);
            std::filesystem::create_symlink("/dev/full", first);
        }
        assert(failures == 0);
    }

    void testStdout() {
        const TemporaryDirectory directory;
        const auto cache = directory.path / "cache";
        std::ofstream(cache) << "0 127.0.0.1 32 22 1 fixture.example\n";
        FILE *const capture = tmpfile();
        assert(capture);
        fflush(stdout);
        const int saved = dup(STDOUT_FILENO);
        assert(saved >= 0 && dup2(fileno(capture), STDOUT_FILENO) >= 0);
        {
            ByeDpiRuntime runtime("-y " + cache.string() + " -y -");
        }
        assert(fflush(stdout) == 0); // Cache writer must not close stdout.
        assert(dup2(saved, STDOUT_FILENO) >= 0);
        close(saved);
        rewind(capture);
        std::string output;
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), capture)) output += buffer;
        fclose(capture);
        assert(output.find("fixture.example") != std::string::npos);
    }
} // namespace

extern "C" int realAccept4(int fd, sockaddr *address, socklen_t *size, int flags) asm("__real_accept4");
extern "C" int wrapAccept4(int fd, sockaddr *address, socklen_t *size, int flags) asm("__wrap_accept4");
extern "C" int wrapAccept4(const int fd, sockaddr *address, socklen_t *size, const int flags) {
    if (const int error = nextAcceptError.exchange(0); error != 0) {
        errno = error;
        return -1;
    }
    return realAccept4(fd, address, size, flags);
}

extern "C" int realEpollWait(int fd, epoll_event *events, int count, int timeout) asm("__real_epoll_wait");
extern "C" int wrapEpollWait(int fd, epoll_event *events, int count, int timeout) asm("__wrap_epoll_wait");
extern "C" int wrapEpollWait(const int fd, epoll_event *events, const int count, const int timeout) {
    if (const int error = nextPollError.exchange(0); error != 0) {
        errno = error;
        return -1;
    }
    return realEpollWait(fd, events, count, timeout);
}

int main() {
    testFatal(false, false);
    testFatal(true, false);
    testFatal(false, true);
    testStartupFailureDoesNotOverwriteCache();
    testPersistence();
    testStdout();
}
