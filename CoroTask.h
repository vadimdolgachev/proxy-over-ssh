#ifndef PROXY_OVER_SSH_COROTASK_H
#define PROXY_OVER_SSH_COROTASK_H

#include <algorithm>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <coroutine>
#include <exception>
#include <mutex>
#include <ranges>
#include <stop_token>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sys/epoll.h>

#include "CancellationToken.h"
#include "CompletionSignal.h"
#include "FdUtils.h"
#include "Timer.h"

class Endpoint;
class Socket;

class EpollScheduler final {
    struct CoroEntry final {
        uint32_t events{};
        std::coroutine_handle<> h;
    };

    class ThreadPool final {
        std::mutex queueMutex;
        std::condition_variable_any cv;
        std::vector<std::coroutine_handle<>> queue;
        std::vector<std::jthread> workers;

    public:
        void enqueue(std::coroutine_handle<> h);

        void worker(const std::stop_token &st);

        void stopAndWait();

        explicit ThreadPool(size_t numThreads);
    };

public:
    using PollEvents = uint32_t;
    static constexpr PollEvents PollIn = EPOLLIN;
    static constexpr PollEvents PollOut = EPOLLOUT;
    static constexpr PollEvents PollErr = EPOLLERR;
    static constexpr PollEvents PollHUp = EPOLLHUP;
    static constexpr PollEvents PollRdHUp = EPOLLRDHUP;

    explicit EpollScheduler(const CancellationTokenSource &cts_);

    EpollScheduler(const EpollScheduler &) = delete;

    EpollScheduler &operator=(const EpollScheduler &) = delete;

    void add(uint32_t events, int fd, std::coroutine_handle<> coro);

    void remove(int fd, std::coroutine_handle<> coro);

    void forceRemoveFd(int fd);

    void run();

    [[nodiscard]] const CancellationTokenSource &getCancellationTokenSource() const;

private:
    struct FdState {
        std::vector<CoroEntry> coros;
        uint32_t registeredEvents = 0;
    };

    using FdStates = std::unordered_map<int, FdState>;

    static uint32_t calculateRemainingEvents(const FdState &state);

    void updateEpollRegistration(FdStates::iterator it);

    const UniqueFd epollFd;
    CompletionSignal wakeupSignal;
    std::mutex schedulerMutex;
    FdStates fdStates;
    std::vector<std::coroutine_handle<>> pendingResumes;
    std::unique_ptr<ThreadPool> threadPool;
    const CancellationTokenSource &cts;
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

    [[nodiscard]] CancellationToken getCancellationToken() const {
        return getScheduler()->getCTS()->getToken();
    }

private:
    T *sched = nullptr;
    const CancellationTokenSource *cancellationTokenSource = nullptr;
};

struct TimerAwaiter final : SchedulerAware<EpollScheduler> {
    explicit TimerAwaiter(const std::chrono::nanoseconds delay_) :
        delay(delay_) {
    }

    [[nodiscard]] bool await_ready() const noexcept {
        return delay.count() == 0;
    }

    void await_suspend(const std::coroutine_handle<> h) {
        coroHandle = h;
        timer.arm(delay);
        this->getScheduler()->add(EpollScheduler::PollIn, timer.getFd(), h);
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

struct GetScheduler final : SchedulerAware<EpollScheduler> {
    [[nodiscard]] bool await_ready() const noexcept {
        return true;
    }

    void await_suspend(std::coroutine_handle<>) noexcept {
    }

    [[nodiscard]] EpollScheduler *await_resume() const noexcept {
        return this->getScheduler();
    }
};

struct GetCancellationToken : SchedulerAware<EpollScheduler> {
    [[nodiscard]] bool await_ready() const noexcept {
        return true;
    }

    void await_suspend(std::coroutine_handle<>) noexcept {
    }

    [[nodiscard]] CancellationToken await_resume() const noexcept {
        return getScheduler()->getCancellationTokenSource().getToken();
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

    std::coroutine_handle<Promise> handle;
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
    using PromiseBase = std::conditional_t<std::is_void_v<T>, PromiseVoid<promise_type>, PromiseValue<T, promise_type>>;

    struct promise_type final : PromiseBase<promise_type> {
        CoroTask get_return_object() {
            return CoroTask{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
    };

    using Awaiter =
            std::conditional_t<std::is_void_v<T>, CoroTaskAwaiterVoid<promise_type>, CoroTaskAwaiter<promise_type, T>>;

    explicit CoroTask(const std::coroutine_handle<promise_type> h) :
        handle(h) {
    }

    CoroTask(CoroTask &&other) noexcept :
        handle(std::exchange(other.handle, nullptr)) {
    }

    CoroTask &operator=(CoroTask &&other) noexcept = delete;

    CoroTask(CoroTask &) = delete;

    ~CoroTask() {
        if (!detached && handle != nullptr) {
            handle.destroy();
        }
    }

    void start(EpollScheduler &scheduler) {
        if (handle == nullptr || handle.done()) {
            return;
        }
        handle.promise().setScheduler(&scheduler);
        handle.resume();
        if (handle.done()) {
            if (const auto exception = std::move(handle.promise().exception)) {
                std::rethrow_exception(exception);
            }
        }
    }

    void detach(EpollScheduler &scheduler) {
        if (handle == nullptr || handle.done()) {
            return;
        }
        handle.promise().setScheduler(&scheduler);
        handle.promise().detached = true;
        detached = true;
        handle.resume();
    }

    auto operator co_await() const noexcept {
        return Awaiter{handle};
    }

    void setScheduler(EpollScheduler *s) noexcept {
        handle.promise().setScheduler(s);
    }

private:
    std::coroutine_handle<promise_type> handle;
    bool detached = false;
};

#endif // PROXY_OVER_SSH_COROTASK_H
