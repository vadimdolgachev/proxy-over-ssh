#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <fcntl.h>
#include <future>
#include <poll.h>
#include <pthread.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <vector>

#include "ByeDpiRuntime.h"
#include "Socks5Client.h"

using namespace CoroLite;

namespace {
    std::atomic_bool failNextSignalSetup = false;
}

extern "C" int __real_pthread_sigmask(int how, const sigset_t *set, sigset_t *oldSet);

extern "C" int __wrap_pthread_sigmask(int how, const sigset_t *set, sigset_t *oldSet) {
    if (how == SIG_BLOCK && set != nullptr && sigismember(set, SIGPIPE) == 1 && failNextSignalSetup.exchange(false)) {
        return EINVAL;
    }
    return __real_pthread_sigmask(how, set, oldSet);
}

namespace {
    class Fd {
    public:
        explicit Fd(int value) :
            descriptor(value) {
            assert(value >= 0);
        }
        ~Fd() {
            close(descriptor);
        }
        Fd(const Fd &) = delete;
        Fd &operator=(const Fd &) = delete;
        int get() const {
            return descriptor;
        }

    private:
        int descriptor;
    };

    void waitFor(int fd, short events) {
        pollfd descriptor{fd, events, 0};
        int result;
        do {
            result = poll(&descriptor, 1, 5000);
        } while (result < 0 && errno == EINTR);
        assert(result == 1);
    }

    void sendAll(int fd, const std::string &data) {
        std::size_t offset = 0;
        while (offset < data.size()) {
            waitFor(fd, POLLOUT);
            const auto count = send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
            if (count < 0 && (errno == EAGAIN || errno == EINTR))
                continue;
            assert(count > 0);
            offset += static_cast<std::size_t>(count);
        }
    }

    std::string readExact(int fd, std::size_t size) {
        std::string result(size, '\0');
        std::size_t offset = 0;
        while (offset < size) {
            waitFor(fd, POLLIN);
            const auto count = recv(fd, result.data() + offset, size - offset, 0);
            if (count < 0 && (errno == EAGAIN || errno == EINTR))
                continue;
            assert(count > 0);
            offset += static_cast<std::size_t>(count);
        }
        return result;
    }

    ResultCode negotiate(int fd, const Endpoint &target) {
        Socks5Client handshake(target);
        ResultCode result;
        while ((result = handshake.advance(fd)) == ResultCode::ErrAgain) {
            waitFor(fd, handshake.wantsRead() ? POLLIN : POLLOUT);
        }
        return result;
    }

    int connectLocal(std::uint16_t port) {
        const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        assert(fd >= 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        const int result = connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address));
        assert(result == 0 || errno == EINPROGRESS);
        waitFor(fd, POLLOUT);
        int error = 0;
        socklen_t length = sizeof(error);
        assert(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0);
        return fd;
    }

    void testTunnel(std::string_view options) {
        Fd listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        assert(bind(listener.get(), reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
        socklen_t length = sizeof(address);
        assert(getsockname(listener.get(), reinterpret_cast<sockaddr *>(&address), &length) == 0);
        assert(listen(listener.get(), 8) == 0);

        constexpr int Connections = 4;
        const std::string banner = "SSH-2.0-embedded-test\r\n";
        const std::string payload = std::string(40000, 'x') + std::string(40000, 'y');
        auto server = std::async(std::launch::async, [&] {
            std::vector<std::future<void>> workers;
            for (int i = 0; i < Connections; ++i) {
                waitFor(listener.get(), POLLIN);
                const int accepted = accept(listener.get(), nullptr, nullptr);
                assert(accepted >= 0);
                workers.push_back(std::async(std::launch::async, [&, accepted] {
                    Fd connection(accepted);
                    sendAll(connection.get(), banner); // SSH sends a banner before receiving application data.
                    assert(readExact(connection.get(), payload.size()) == payload);
                    sendAll(connection.get(), payload);
                }));
            }
            for (auto &worker: workers)
                worker.get();
        });
        std::atomic_int protectedSockets = 0;
        {
            ByeDpiRuntime runtime(options, [&](int fd) {
                sockaddr_storage peer{};
                socklen_t peerLength = sizeof(peer);
                assert(getpeername(fd, reinterpret_cast<sockaddr *>(&peer), &peerLength) < 0 && errno == ENOTCONN);
                ++protectedSockets;
                return true;
            });
            std::vector<std::future<void>> clients;
            for (int i = 0; i < Connections; ++i) {
                clients.push_back(std::async(std::launch::async, [&] {
                    Fd connection(connectLocal(runtime.port()));
                    assert(negotiate(connection.get(), Endpoint(address)) == ResultCode::Ok);
                    assert(readExact(connection.get(), banner.size()) == banner);
                    sendAll(connection.get(), payload);
                    assert(readExact(connection.get(), payload.size()) == payload);
                }));
            }
            for (auto &client: clients)
                client.get();
            assert(protectedSockets == Connections);
        }
        server.get();
    }

    void testInvalidArguments() {
        for (const auto *options: {"--not-an-option", "--split", "'unfinished", "--daemon", "--pidfile /tmp/no-pid",
                                   "--ip 0.0.0.0", "--port 10804", "--transparent", "--protect-path ignored",
                                   "--connect-to 127.0.0.1:22", "unexpected-positional-value"}) {
            bool rejected = false;
            try {
                ByeDpiRuntime runtime(options);
            } catch (const std::exception &) {
                rejected = true;
            }
            assert(rejected);
            ByeDpiRuntime retry("--split 2"); // Parser/global state must recover after every failure.
            assert(retry.isRunning());
        }
    }

    void testProtectionFailure() {
        std::atomic_int attempts = 0;
        ByeDpiRuntime runtime("--split 2", [&](int) {
            ++attempts;
            return false;
        });
        Fd connection(connectLocal(runtime.port()));
        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        destination.sin_port = htons(22);
        assert(negotiate(connection.get(), Endpoint(destination)) == ResultCode::ErrIO);
        assert(attempts == 1);
    }

    void testStopWithPendingClient() {
        auto runtime = std::make_unique<ByeDpiRuntime>("--split 2");
        Fd connection(connectLocal(runtime->port()));
        runtime.reset();
        waitFor(connection.get(), POLLIN);
        char byte = 0;
        const auto result = recv(connection.get(), &byte, 1, 0);
        assert(result == 0 || (result < 0 && errno == ECONNRESET));
    }

    sigset_t currentSignalMask() {
        sigset_t mask;
        assert(pthread_sigmask(SIG_SETMASK, nullptr, &mask) == 0);
        return mask;
    }

    void assertSignalMasksEqual(const sigset_t &first, const sigset_t &second) {
        for (int signal = 1; signal < NSIG; ++signal) {
            assert(sigismember(&first, signal) == sigismember(&second, signal));
        }
    }

    void testSignalSetupFailure() {
        const auto before = currentSignalMask();
        failNextSignalSetup.store(true);
        bool rejected = false;
        try {
            ByeDpiRuntime runtime("--split 2");
        } catch (const std::system_error &error) {
            rejected = true;
            assert(error.code() == std::error_code(EINVAL, std::generic_category()));
        }
        assert(rejected && !failNextSignalSetup.load());
        assertSignalMasksEqual(before, currentSignalMask());
        // Cleanup must join the failed worker, release the singleton and permit a fresh start.
        for (int i = 0; i < 2; ++i) {
            ByeDpiRuntime retry("--split 2");
            assert(retry.isRunning());
            assertSignalMasksEqual(before, currentSignalMask());
        }
        assertSignalMasksEqual(before, currentSignalMask());
    }

    void testSigpipeInWorker() {
        // This mode runs in its own CTest process: an unblocked SIGPIPE must fail the test.
        struct sigaction disposition{};
        disposition.sa_handler = SIG_DFL;
        assert(sigemptyset(&disposition.sa_mask) == 0);
        assert(sigaction(SIGPIPE, &disposition, nullptr) == 0);
        sigset_t signal;
        assert(sigemptyset(&signal) == 0);
        assert(sigaddset(&signal, SIGPIPE) == 0);
        assert(pthread_sigmask(SIG_UNBLOCK, &signal, nullptr) == 0);
        const auto before = currentSignalMask();
        std::atomic_bool exercised = false;
        {
            ByeDpiRuntime runtime("--split 2", [&](int) {
                const auto workerMask = currentSignalMask();
                assert(sigismember(&workerMask, SIGPIPE) == 1);
                Fd listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
                sockaddr_in address{};
                address.sin_family = AF_INET;
                address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                assert(bind(listener.get(), reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
                socklen_t length = sizeof(address);
                assert(getsockname(listener.get(), reinterpret_cast<sockaddr *>(&address), &length) == 0);
                assert(listen(listener.get(), 1) == 0);
                Fd sender(connectLocal(ntohs(address.sin_port)));
                Fd peer(accept(listener.get(), nullptr, nullptr));
                assert(shutdown(sender.get(), SHUT_WR) == 0);
                // Deliberately omit MSG_NOSIGNAL: this also covers Android's fortified send path.
                assert(send(sender.get(), "x", 1, 0) == -1 && errno == EPIPE);
                int pipeFds[2];
                assert(pipe(pipeFds) == 0);
                Fd input(pipeFds[0]);
                Fd output(pipeFds[1]);
                assert(write(output.get(), "x", 1) == 1);
                assert(splice(input.get(), nullptr, sender.get(), nullptr, 1, 0) == -1 && errno == EPIPE);
                sigset_t pending;
                assert(sigpending(&pending) == 0);
                assert(sigismember(&pending, SIGPIPE) == 1);
                exercised.store(true);
                return false;
            });
            assert(runtime.isRunning());
            assertSignalMasksEqual(before, currentSignalMask());
            Fd connection(connectLocal(runtime.port()));
            sockaddr_in destination{};
            destination.sin_family = AF_INET;
            destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            destination.sin_port = htons(22);
            assert(negotiate(connection.get(), Endpoint(destination)) == ResultCode::ErrIO);
            assert(exercised.load());
        } // A pending SIGPIPE must remain blocked through worker teardown.
        assertSignalMasksEqual(before, currentSignalMask());
        struct sigaction after{};
        assert(sigaction(SIGPIPE, nullptr, &after) == 0);
        assert(after.sa_handler == SIG_DFL);
    }
} // namespace

int main(int argc, char **argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--sigpipe") {
        testSigpipeInWorker();
        return 0;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--signal-setup-failure") {
        testSignalSetupFailure();
        return 0;
    }
    assert(argc == 1);
    struct sigaction before{}, after{};
    assert(sigaction(SIGPIPE, nullptr, &before) == 0);
    testInvalidArguments();
    for (int i = 0; i < 3; ++i) {
        ByeDpiRuntime runtime("--split '2' --mod-http=\"h,d\"");
        bool rejected = false;
        try {
            ByeDpiRuntime duplicate("");
        } catch (const std::runtime_error &) {
            rejected = true;
        }
        assert(rejected && runtime.isRunning());
    }
    testTunnel("--split 2");
    testTunnel(DefaultByeDpiArgs);
    testProtectionFailure();
    testStopWithPendingClient();
    assert(sigaction(SIGPIPE, nullptr, &after) == 0);
    assert(before.sa_handler == after.sa_handler);
}
