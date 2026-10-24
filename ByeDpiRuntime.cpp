#include <cerrno>
#include <chrono>
#include <csignal>
#include <future>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <utility>

#include "ByeDpiRuntime.h"
#include "Logger.h"
#include "byedpi/Arguments.h"
#include "byedpi/Engine.h"

using namespace CoroLite;

namespace {
    std::atomic_flag engineInUse = ATOMIC_FLAG_INIT;

    int blockSigpipe() noexcept {
        sigset_t signals;
        if (sigemptyset(&signals) != 0 || sigaddset(&signals, SIGPIPE) != 0) {
            return errno;
        }
        return pthread_sigmask(SIG_BLOCK, &signals, nullptr);
    }
} // namespace

ByeDpiRuntime::ByeDpiRuntime(const std::string_view options, SocketProtector protector, FailureCallback onFailure) :
    socketProtector(std::move(protector)),
    failureCallback(std::move(onFailure)),
    arguments(ByeDpi::Detail::splitArguments(options)) {
    if (arguments.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::invalid_argument("Too many ByeDPI arguments");
    }
    for (auto &argument: arguments) {
        argumentPointers.push_back(argument.data());
    }
    argumentPointers.push_back(nullptr);
    if (engineInUse.test_and_set()) {
        throw std::runtime_error("Only one embedded ByeDPI instance may run per process");
    }
    try {
        engine = byedpi_engine_create(static_cast<int>(arguments.size()), argumentPointers.data(), protectSocket, this);
        if (engine == nullptr) {
            throw std::runtime_error("Unable to initialize embedded ByeDPI; check its arguments and native log");
        }
        std::promise<int> startup;
        auto ready = startup.get_future();
        worker = std::thread([this, startup = std::move(startup)]() mutable {
            if (const int signalError = blockSigpipe(); signalError != 0) {
                startup.set_value(signalError);
                return;
            }
            // Keep SIGPIPE blocked until thread exit, including any pending signal from splice().
            running.store(true);
            startup.set_value(0);
            const int result = byedpi_engine_run(engine);
            running.store(false);
            if (result != 0 && !stopping.load()) {
                try {
                    log_e("Embedded ByeDPI event loop stopped unexpectedly: errno={}\n", -result);
                } catch (...) {
                }
                try {
                    if (failureCallback) {
                        failureCallback(-result);
                    }
                } catch (...) {
                    // Never let a host callback unwind out of the worker thread.
                }
            }
        });
        if (const int signalError = ready.get(); signalError != 0) {
            throw std::system_error(signalError, std::generic_category(), "Unable to block SIGPIPE in ByeDPI thread");
        }
        log_d("Embedded ByeDPI listening on 127.0.0.1:{}\n", port());
    } catch (...) {
        if (worker.joinable()) {
            requestStop();
            worker.join();
        }
        byedpi_engine_destroy(engine);
        engineInUse.clear();
        throw;
    }
}

ByeDpiRuntime::~ByeDpiRuntime() {
    requestStop();
    if (worker.joinable()) {
        worker.join();
    }
    byedpi_engine_destroy(engine);
    engineInUse.clear();
}

void ByeDpiRuntime::requestStop() noexcept {
    if (!stopping.exchange(true)) {
        byedpi_engine_request_stop(engine);
    }
}

std::uint16_t ByeDpiRuntime::port() const noexcept {
    return byedpi_engine_port(engine);
}

bool ByeDpiRuntime::isRunning() const noexcept {
    return running.load();
}

int ByeDpiRuntime::protectSocket(const int fd, void *const context) noexcept {
    const auto *const runtime = static_cast<ByeDpiRuntime *>(context);
    try {
        if (!runtime->socketProtector || runtime->socketProtector(fd)) {
            return 0;
        }
    } catch (...) {
    }
    log_e("Unable to protect outgoing ByeDPI socket from the VPN\n");
    return -1;
}
