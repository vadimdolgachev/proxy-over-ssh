#ifndef PROXY_OVER_SSH_COROTASK_H
#define PROXY_OVER_SSH_COROTASK_H

#include <algorithm>
#include <chrono>
#include <coroutine>
#include <cerrno>
#include <unordered_map>
#include <utility>
#include <cassert>
#include <functional>
#include <ranges>
#include <system_error>
#include <vector>

#include <sys/epoll.h>

#include "Logger.h"
#include "FdUtils.h"
#include "Timer.h"
#include "Constants.h"

class Endpoint;
class Socket;

class EpollScheduler final {
    struct CoroEntry final {
        uint32_t events;
        std::coroutine_handle<> h;
    };

public:
    using PollEvents = EPOLL_EVENTS;

    explicit EpollScheduler(std::function<bool()> stopToken_)
        : epollFd(epoll_create1(EPOLL_CLOEXEC)),
          stopToken(std::move(stopToken_)) {
        if (epollFd.get() < 0) {
            throw std::runtime_error("Epoll creation failed");
        }
        pendingResumes.reserve(16);
    }

    EpollScheduler(const EpollScheduler &) = delete;

    EpollScheduler &operator=(const EpollScheduler &) = delete;

    void add(const uint32_t events, const int fd, const std::coroutine_handle<> coro) {
        auto &[coros, registeredEvents] = fdStates[fd];
        coros.push_back({events, coro});

        const uint32_t desired = registeredEvents | events;
        if (desired == registeredEvents) {
            return;
        }

        const int op = registeredEvents == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        epoll_event ev{};
        ev.events = desired;
        ev.data.fd = fd;

        if (epoll_ctl(epollFd.get(), op, fd, &ev) < 0) {
            const int err = errno;
            coros.pop_back();
            if (coros.empty()) {
                fdStates.erase(fd);
            }
            throw std::system_error(err, std::system_category(), "Epoll add failed");
        }
        registeredEvents = desired;
    }

    void remove(const int fd, const std::coroutine_handle<> coro) {
        const auto it = fdStates.find(fd);
        if (it == fdStates.end()) {
            return;
        }

        auto &coros = it->second.coros;
        const auto coroIt = std::ranges::find_if(coros, [&](const CoroEntry &e) {
            return e.h == coro;
        });
        if (coroIt != coros.end()) {
            coros.erase(coroIt);
            updateEpollRegistration(it);
        }
    }

    void forceRemoveFd(const int fd) {
        fdStates.erase(fd);
        epoll_ctl(epollFd.get(), EPOLL_CTL_DEL, fd, nullptr);
    }

    void run() {
        std::array<epoll_event, Constants::EPOLL_BATCH_SIZE> events = {};

        int iterationCount = 0;
        auto lastCheck = std::chrono::steady_clock::now();

        while (stopToken ? !stopToken() : true) {
            if (const int size = epoll_wait(epollFd.get(), events.data(), events.size(), Constants::EPOLL_TIMEOUT_MS);
                size > 0) {
                pendingResumes.clear();

                for (size_t i = 0; i < static_cast<size_t>(size); ++i) {
                    const int eventFd = events[i].data.fd;
                    const uint32_t occurredEvents = events[i].events;

                    auto fdIt = fdStates.find(eventFd);
                    if (fdIt == fdStates.end()) {
                        epoll_ctl(epollFd.get(), EPOLL_CTL_DEL, eventFd, nullptr);
                        continue;
                    }

                    auto &coros = fdIt->second.coros;

                    for (auto coroIt = coros.begin(); coroIt != coros.end();) {
                        if (coroIt->events & occurredEvents) {
                            if (std::ranges::find(pendingResumes, coroIt->h) == pendingResumes.end()) {
                                pendingResumes.push_back(coroIt->h);
                            }
                            coroIt = coros.erase(coroIt);
                        } else {
                            ++coroIt;
                        }
                    }

                    updateEpollRegistration(fdIt);
                }

                for (auto h: pendingResumes) {
                    h.resume();
                }

                iterationCount++;
            }

            if (auto now = std::chrono::steady_clock::now();
                now - lastCheck >= std::chrono::milliseconds(Constants::BUSY_LOOP_CHECK_INTERVAL_MS)) {
                if (iterationCount > Constants::BUSY_LOOP_THRESHOLD) {
                    log_e("WARNING: Busy loop detected! {} epoll iterations in 100ms\n", iterationCount);
                }
                iterationCount = 0;
                lastCheck = now;
            }
        }
    }

private:
    struct FdState {
        std::vector<CoroEntry> coros;
        uint32_t registeredEvents = 0;
    };

    using FdStates = std::unordered_map<int, FdState>;

    static uint32_t calculateRemainingEvents(const FdState &state) {
        uint32_t remaining = 0;
        for (const auto &coro: state.coros) {
            remaining |= coro.events;
        }
        return remaining;
    }

    void updateEpollRegistration(const FdStates::iterator it) {
        const int fd = it->first;
        auto &state = it->second;

        const uint32_t remaining = calculateRemainingEvents(state);

        if (state.coros.empty()) {
            epoll_ctl(epollFd.get(), EPOLL_CTL_DEL, fd, nullptr);
            fdStates.erase(it);
        } else if (remaining != state.registeredEvents) {
            epoll_event ev{};
            ev.events = remaining;
            ev.data.fd = fd;
            epoll_ctl(epollFd.get(), EPOLL_CTL_MOD, fd, &ev);
            state.registeredEvents = remaining;
        }
    }

    const UniqueFd epollFd;
    FdStates fdStates;
    std::vector<std::coroutine_handle<> > pendingResumes;
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
        return delay.count() == 0;
    }

    void await_suspend(const std::coroutine_handle<> h) {
        coroHandle = h;
        timer.arm(delay);
        this->getScheduler()->add(EpollScheduler::PollEvents::EPOLLIN, timer.getFd(), h);
    }

    void await_resume() noexcept {
        timer.drain();
        this->getScheduler()->remove(timer.getFd(), coroHandle);
    }

private:
    std::chrono::nanoseconds delay;
    Timer timer;
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
        return handle == nullptr || handle.done();
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

    Resume await_resume() {
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

    void await_resume() {
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
        if (handle != nullptr) {
            handle.destroy();
        }
    }

    void start(EpollScheduler &scheduler) const {
        if (handle != nullptr && !handle.done()) {
            handle.promise().setScheduler(&scheduler);
            handle.resume();
        }
    }

    // Detach the coroutine for fire-and-forget execution
    // The coroutine will destroy itself when it completes
    void detach(EpollScheduler &scheduler) {
        if (handle != nullptr && !handle.done()) {
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

#endif // PROXY_OVER_SSH_COROTASK_H
