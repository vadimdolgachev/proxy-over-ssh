#ifndef COROTASK_H
#define COROTASK_H

#include <chrono>
#include <coroutine>
#include <cstdlib>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <cassert>

#include <sys/epoll.h>
#include <sys/timerfd.h>

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

    int release() noexcept {
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
        int fd{};
        std::coroutine_handle<> h;
    };

public:
    EpollScheduler() : epollFd(epoll_create1(EPOLL_CLOEXEC)) {
        if (epollFd.get() < 0) {
            throw std::runtime_error("Epoll creation failed");
        }
    }

    EpollScheduler(const EpollScheduler &) = delete;

    EpollScheduler &operator=(const EpollScheduler &) = delete;

    void add(const int fd, const std::coroutine_handle<> h) {
        epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.ptr = h.address();

        if (!handles.try_emplace(h.address(), fd, h).second) {
            std::abort();
        }

        if (epoll_ctl(epollFd.get(), EPOLL_CTL_ADD, fd, &ev) < 0) {
            std::abort();
        }
    }

    void run() {
        std::array<epoll_event, 16> events = {};
        while (true) {
            if (const int n = epoll_wait(epollFd.get(), events.data(), events.size(), -1); n > 0) {
                for (size_t i = 0; i < static_cast<size_t>(n); ++i) {
                    auto addr = events[i].data.ptr;
                    const auto [fd, h] = handles[addr];
                    handles.erase(addr);
                    rem(fd);
                    h.resume();
                }
            } else {
                abort();
            }
        }
    }

private:
    void rem(const int fd) const {
        if (epoll_ctl(epollFd.get(), EPOLL_CTL_DEL, fd, nullptr) < 0) {
            abort();
        }
    }

    const UniqueFd epollFd;
    std::unordered_map<void *, Entry> handles;
};

struct SchedulerAware {
    void setScheduler(EpollScheduler *s) noexcept {
        assert(sched == nullptr);
        sched = s;
    }

    [[nodiscard]] EpollScheduler *getScheduler() const noexcept {
        return sched;
    }

private:
    EpollScheduler *sched = nullptr;
};

struct TimerAwaiter final : SchedulerAware {
    explicit TimerAwaiter(const std::chrono::nanoseconds delay_) : delay(delay_) {
    }

    [[nodiscard]] bool await_ready() const noexcept {
        return false;
    }

    void await_suspend(const std::coroutine_handle<> h) {
        timerFd.reset(timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC));
        if (timerFd.get() < 0) {
            std::terminate();
        }

        itimerspec spec{};
        spec.it_value.tv_sec = delay.count() / 1'000'000'000;
        spec.it_value.tv_nsec = delay.count() % 1'000'000'000;
        timerfd_settime(timerFd.get(), 0, &spec, nullptr);

        getScheduler()->add(timerFd.get(), h);
    }

    void await_resume() {
        uint64_t expirations;
        read(timerFd.get(), &expirations, sizeof(expirations));
    }

private:
    std::chrono::nanoseconds delay{};
    UniqueFd timerFd{};
};


template<typename Base>
struct PromiseBase : SchedulerAware {
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
    using PromiseBase = std::conditional_t<std::is_void_v<T>, PromiseVoid<promise_type>, PromiseValue<T, promise_type> >
    ;

    struct promise_type : PromiseBase<promise_type> {
        CoroTask get_return_object() {
            return CoroTask{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
    };

    using Awaiter = std::conditional_t<std::is_void_v<T>, CoroTaskAwaiterVoid<promise_type>, CoroTaskAwaiter<
        promise_type, T> >;

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

    auto operator co_await() const noexcept {
        return Awaiter{handle};
    }

    void setScheduler(EpollScheduler *s) noexcept {
        handle.promise().setScheduler(s);
    }

private:
    std::coroutine_handle<promise_type> handle = nullptr;
};

#endif
