#ifndef COROTASK_H
#define COROTASK_H

#include <chrono>
#include <coroutine>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <cassert>
#include <functional>
#include <iostream>
#include <system_error>

#include <sys/epoll.h>
#include <sys/timerfd.h>

class Endpoint;
class Socket;

struct CloseFdFinalizer final {
    void operator()(const int fd) const noexcept {
        close(fd);
    }
};

template<typename Finalizer = CloseFdFinalizer>
class UniqueFdBasic final {
public:
    explicit UniqueFdBasic(const int fd_ = -1) noexcept : fd(fd_) {
    }

    UniqueFdBasic(const UniqueFdBasic &) = delete;

    UniqueFdBasic &operator=(const UniqueFdBasic &) = delete;

    UniqueFdBasic(UniqueFdBasic &&other) noexcept : fd(other.release()) {
    }

    UniqueFdBasic &operator=(UniqueFdBasic &&other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    void reset(const int newFd) noexcept {
        if (fd == newFd) {
            return;
        }
        if (fd >= 0) {
            Finalizer()(fd);
        }
        fd = newFd;
    }

    [[nodiscard]] int release() noexcept {
        return std::exchange(fd, -1);
    }

    ~UniqueFdBasic() noexcept {
        if (fd >= 0) {
            Finalizer()(fd);
        }
    }

    [[nodiscard]] int get() const noexcept {
        return fd;
    }

private:
    int fd = -1;
};

using UniqueFd = UniqueFdBasic<>;

class EpollScheduler final {
    struct Entry final {
        int fd = -1;
        std::coroutine_handle<> h;
    };

public:
    using PollEvents = EPOLL_EVENTS;

    explicit EpollScheduler(std::function<bool()> stopToken_) : epollFd(epoll_create1(EPOLL_CLOEXEC)),
                                                                stopToken(std::move(stopToken_)) {
        if (epollFd.get() < 0) {
            throw std::runtime_error("Epoll creation failed");
        }
    }

    EpollScheduler(const EpollScheduler &) = delete;

    EpollScheduler &operator=(const EpollScheduler &) = delete;

    void add(const uint32_t events, const int fd, const std::coroutine_handle<> coro) {
        epoll_event ev{};
        ev.events = events;
        ev.data.ptr = coro.address();

        auto [it, inserted] = handles.try_emplace(coro.address(), fd, coro);
        if (!inserted) {
            throw std::runtime_error("Coroutine handler already exists");
        }

        if (epoll_ctl(epollFd.get(), EPOLL_CTL_ADD, fd, &ev)) {
            const int err = errno;
            handles.erase(it); // Rollback insertion
            throw std::system_error(err, std::system_category(), "Epoll add failed");
        }
    }

    void remove(const int fd, const std::coroutine_handle<> coro) {
        if (handles.erase(coro.address()) > 0) {
            if (epoll_ctl(epollFd.get(), EPOLL_CTL_DEL, fd, nullptr) < 0) {
                const int err = errno;
                // Ignore EBADF (fd already closed) and ENOENT (entry not found)
                if (err != EBADF && err != ENOENT) {
                    throw std::system_error(err, std::system_category(), "Epoll remove failed");
                }
                std::cout << "Epoll remove ignored error " << err << " for fd=" << fd << "\n";
            }
        }
    }

    void modify(const int fd, const uint32_t events, const std::coroutine_handle<> coro) {
        if (!handles.contains(coro.address())) {
            return;
        }

        epoll_event ev{};
        ev.events = events;
        ev.data.ptr = coro.address();

        if (epoll_ctl(epollFd.get(), EPOLL_CTL_MOD, fd, &ev) < 0) {
            const int err = errno;
            // Ignore EBADF (fd already closed) and ENOENT (entry not found)
            if (err != EBADF && err != ENOENT) {
                throw std::system_error(err, std::system_category(), "Epoll modify failed");
            }
        }
    }

    void run() {
        std::array<epoll_event, 16> events = {};
        while (true) {
            if (const int size = epoll_wait(epollFd.get(), events.data(), events.size(), 10'000); size > 0) {
                for (size_t i = 0; i < static_cast<size_t>(size); ++i) {
                    auto addr = events[i].data.ptr;
                    const auto [fd, h] = handles[addr];
                    remove(fd, h);
                    h.resume();
                }
            } else if (stopToken && stopToken()) {
                break;
            }
        }
    }

private:
    const UniqueFd epollFd;
    std::unordered_map<void *, Entry> handles;
    std::function<bool()> stopToken;
};

template<typename T>
struct SchedulerAware {
    void setScheduler(T *s) noexcept {
        assert(sched == nullptr);
        sched = s;
    }

    [[nodiscard]] T *getScheduler() const noexcept {
        return sched;
    }

private:
    T *sched = nullptr;
};

struct TimerAwaiter final : SchedulerAware<EpollScheduler> {
    explicit TimerAwaiter(const std::chrono::nanoseconds delay_) : delay(delay_) {
    }

    [[nodiscard]] bool await_ready() const noexcept {
        return false;
    }

    void await_suspend(const std::coroutine_handle<> h) {
        coroHandle = h;
        timerFd.reset(timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC));
        if (timerFd.get() < 0) {
            throw std::system_error(errno, std::system_category(), "timerfd_create failed");
        }

        itimerspec spec{};
        spec.it_value.tv_sec = delay.count() / 1'000'000'000;
        spec.it_value.tv_nsec = delay.count() % 1'000'000'000;
        timerfd_settime(timerFd.get(), 0, &spec, nullptr);

        this->getScheduler()->add(EpollScheduler::PollEvents::EPOLLIN, timerFd.get(), h);
    }

    void await_resume() {
        uint64_t expirations;
        [[maybe_unused]] auto r = read(timerFd.get(), &expirations, sizeof(expirations));
        // Remove from scheduler before timerFd is destroyed
        this->getScheduler()->remove(timerFd.get(), coroHandle);
    }

private:
    std::chrono::nanoseconds delay{};
    UniqueFd timerFd{};
    std::coroutine_handle<> coroHandle;
};

template<typename Base>
struct PromiseBase : SchedulerAware<EpollScheduler> {
    std::suspend_always initial_suspend() {
        return {};
    }

    auto final_suspend() noexcept {
        struct Awaiter final {
            bool await_ready() noexcept {
                return false;
            }

            void await_suspend(std::coroutine_handle<Base> h) noexcept {
                if (auto cont = std::exchange(h.promise().continuation, nullptr)) {
                    cont.resume();
                } else if (h.promise().detached) {
                    h.destroy();
                }
            }

            void await_resume() noexcept {
            }
        };
        return Awaiter{};
    }

    void unhandled_exception() {
        exception = std::current_exception();
    }

    template<typename T>
    auto await_transform(T &&a) {
        if constexpr (requires { a.setScheduler(getScheduler()); }) {
            a.setScheduler(getScheduler());
        }
        return std::forward<T>(a);
    }

    std::exception_ptr exception;
    std::coroutine_handle<> continuation = nullptr;
    bool detached = false;
};


template<typename Base>
struct PromiseVoid : PromiseBase<Base> {
    void return_void() noexcept {
    }
};

template<typename T, typename Base>
struct PromiseValue : PromiseBase<Base> {
    std::optional<T> value;

    template<typename U>
    void return_value(U &&v) {
        value.emplace(std::forward<U>(v));
    }
};

struct GetScheduler : SchedulerAware<EpollScheduler> {
    [[nodiscard]] bool await_ready() const noexcept {
        return true;
    }

    void await_suspend(std::coroutine_handle<>) noexcept {
    }

    [[nodiscard]] EpollScheduler *await_resume() const noexcept {
        return this->getScheduler();
    }
};

template<typename Promise>
struct CoroTaskAwaiterBase {
    bool await_ready() noexcept {
        return !handle || handle.done();
    }

    void await_suspend(const std::coroutine_handle<> parent) noexcept {
        handle.promise().continuation = parent;
        handle.resume();
    }

    std::coroutine_handle<Promise> handle = nullptr;
};

template<typename Promise, typename Resume>
struct CoroTaskAwaiter final : CoroTaskAwaiterBase<Promise> {
    using CoroTaskAwaiterBase<Promise>::handle;

    Resume await_resume() noexcept {
        auto &promise = handle.promise();
        if (promise.exception) {
            std::rethrow_exception(promise.exception);
        }
        return std::move(*promise.value);
    }
};

template<typename Promise>
struct CoroTaskAwaiterVoid final : CoroTaskAwaiterBase<Promise> {
    using CoroTaskAwaiterBase<Promise>::handle;

    void await_resume() noexcept {
        if (handle.promise().exception) {
            std::rethrow_exception(handle.promise().exception);
        }
    }
};

template<typename T>
class CoroTask final {
public:
    template<typename promise_type>
    using PromiseBase = std::conditional_t<std::is_void_v<T>,
        PromiseVoid<promise_type>,
        PromiseValue<T, promise_type> >;

    struct promise_type final : PromiseBase<promise_type> {
        CoroTask get_return_object() {
            return CoroTask{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
    };

    using Awaiter = std::conditional_t<std::is_void_v<T>,
        CoroTaskAwaiterVoid<promise_type>,
        CoroTaskAwaiter<promise_type, T> >;

    explicit CoroTask(const std::coroutine_handle<promise_type> h) : handle(h) {
    }

    CoroTask(CoroTask &&other) noexcept
        : handle(std::exchange(other.handle, {})) {
    }

    CoroTask(CoroTask &) = delete;

    ~CoroTask() {
        if (handle) {
            handle.destroy();
        }
    }

    void start(EpollScheduler &scheduler) const {
        if (handle && !handle.done()) {
            handle.promise().setScheduler(&scheduler);
            handle.resume();
        }
    }

    // Detach the coroutine for fire-and-forget execution
    // The coroutine will destroy itself when it completes
    void detach(EpollScheduler &scheduler) {
        if (handle && !handle.done()) {
            handle.promise().setScheduler(&scheduler);
            handle.promise().detached = true;
            handle.resume();
            release();
        }
    }

    auto operator co_await() const noexcept {
        return Awaiter{handle};
    }

    void setScheduler(EpollScheduler *s) noexcept {
        handle.promise().setScheduler(s);
    }

    std::coroutine_handle<promise_type> release() noexcept {
        return std::exchange(handle, {});
    }

private:
    std::coroutine_handle<promise_type> handle = nullptr;
};

#endif
