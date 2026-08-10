#ifndef PROXY_OVER_SSH_COROTASK_H
#define PROXY_OVER_SSH_COROTASK_H

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <coroutine>
#include <exception>
#include <mutex>
#include <ranges>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <sys/epoll.h>

#include "CancellationToken.h"
#include "CompletionSignal.h"
#include "FdUtils.h"
#include "Logger.h"
#include "Timer.h"

class EpollScheduler final {
    struct CoroEntry final {
        uint32_t events{};
        std::coroutine_handle<> handle;
    };

    class ThreadPool final {
        EpollScheduler &scheduler;
        std::mutex queueMutex;
        std::condition_variable_any cv;
        std::vector<std::coroutine_handle<>> queue;
        std::vector<std::jthread> workers;
        bool stopping = false;

    public:
        void enqueue(std::coroutine_handle<> h);

        void worker(const std::stop_token &st);

        void drainAndStop();

        ThreadPool(EpollScheduler &scheduler_, size_t numThreads);
    };

public:
    using PollEvents = uint32_t;
    static constexpr PollEvents PollIn = EPOLLIN;
    static constexpr PollEvents PollOut = EPOLLOUT;
    static constexpr PollEvents PollErr = EPOLLERR;
    static constexpr PollEvents PollHUp = EPOLLHUP;
    static constexpr PollEvents PollRdHUp = EPOLLRDHUP;

    explicit EpollScheduler(const CancellationTokenSource &cts_);

    ~EpollScheduler();

    EpollScheduler(const EpollScheduler &) = delete;

    EpollScheduler &operator=(const EpollScheduler &) = delete;

    void add(uint32_t events, int fd, std::coroutine_handle<> coro);

    void remove(int fd, std::coroutine_handle<> coro);

    void rollbackAdd(int fd, std::coroutine_handle<> coro) noexcept;

    void forceRemoveFd(int fd);

    void run();

    void registerDetached(std::coroutine_handle<> coro);

    void unregisterDetached(std::coroutine_handle<> coro) noexcept;

    [[nodiscard]] const CancellationTokenSource &getCancellationTokenSource() const;

private:
    struct FdState {
        std::vector<CoroEntry> coros;
    };

    using FdStates = std::unordered_map<int, FdState>;

    static uint32_t calculateRemainingEvents(const std::vector<CoroEntry> &coros);

    void applyEpollRegistration(int fd, const std::vector<CoroEntry> &coros) const;

    void collectReadyCoroutines(FdStates::iterator fdIt, uint32_t occurredEvents);

    void enqueuePendingResumes();

    void shutdown() noexcept;

    void onResumeFinished(void *address);

    const UniqueFd epollFd;
    CompletionSignal wakeupSignal;
    std::mutex schedulerMutex;
    FdStates fdStates;
    std::vector<std::coroutine_handle<>> pendingResumes;
    std::unordered_set<void *> scheduledCoros;
    std::mutex detachedMutex;
    std::vector<std::coroutine_handle<>> detachedCoros;
    std::unique_ptr<ThreadPool> threadPool;
    const CancellationTokenSource &cts;
    std::atomic_bool shutdownComplete = false;
};

template<typename T>
struct SchedulerAware {
    void setScheduler(T *const s) noexcept {
        sched = s;
    }

    [[nodiscard]] T *getScheduler() const noexcept {
        return sched;
    }

private:
    T *sched = nullptr;
};

struct TimerAwaiter final : SchedulerAware<EpollScheduler> {
    explicit TimerAwaiter(const std::chrono::nanoseconds delay_, CancellationTokenOpt ct) :
        delay(delay_),
        cancellationToken(std::move(ct)) {
    }

    [[nodiscard]] bool await_ready() const noexcept {
        return delay.count() == 0;
    }

    void await_suspend(const std::coroutine_handle<> h) {
        handle = h;
        if (cancellationToken) {
            this->getScheduler()->add(EpollScheduler::PollIn, cancellationToken.value().getFd(), h);
        }
        timer.arm(delay);
        this->getScheduler()->add(EpollScheduler::PollIn, timer.getFd(), h);
    }

    void await_resume() {
        timer.drain();
        this->getScheduler()->remove(timer.getFd(), handle);

        if (cancellationToken) {
            if (handle) {
                this->getScheduler()->remove(cancellationToken.value().getFd(), handle);
            }
            if (cancellationToken.value().isStopped()) {
                cancellationToken->drain();
                throw CancellationTokenException{};
            }
        }
    }

private:
    std::chrono::nanoseconds delay;
    Timer timer;
    CancellationTokenOpt cancellationToken;
    std::coroutine_handle<> handle;
};

enum class CoroLifecycle {
    Created,
    Started,
    Awaited,
    Detached,
    Completed,
};

template<typename PromiseType>
struct PromiseFinalAwaiter final {
    static constexpr bool await_ready() noexcept {
        return false;
    }

    std::coroutine_handle<> await_suspend(const std::coroutine_handle<PromiseType> coro) noexcept {
        auto &promise = coro.promise();
        const auto previous = promise.lifecycle.exchange(CoroLifecycle::Completed);
        const auto continuation = promise.continuation;
        if (previous == CoroLifecycle::Detached) {
            if (auto *const scheduler = promise.getScheduler()) {
                scheduler->unregisterDetached(coro);
            }
            coro.destroy();
            return std::noop_coroutine();
        }
        return continuation != nullptr ? continuation : std::noop_coroutine();
    }

    void await_resume() const noexcept {
    }
};

template<typename PromiseType>
struct PromiseBase : SchedulerAware<EpollScheduler> {
    auto initial_suspend() noexcept {
        return std::suspend_always{};
    }

    auto final_suspend() noexcept {
        return PromiseFinalAwaiter<PromiseType>{};
    }

    void unhandled_exception() {
        exception = std::current_exception();
    }

    template<typename T>
    decltype(auto) await_transform(T &&a) {
        if constexpr (requires { a.setScheduler(this->getScheduler()); })
            a.setScheduler(this->getScheduler());
        return std::forward<T>(a);
    }

    std::exception_ptr exception;
    std::coroutine_handle<> continuation = nullptr;
    std::atomic<CoroLifecycle> lifecycle = CoroLifecycle::Created;
};

template<typename PromiseType>
struct PromiseVoid : PromiseBase<PromiseType> {
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

struct GetCancellationToken final : SchedulerAware<EpollScheduler> {
    [[nodiscard]] bool await_ready() const noexcept {
        return true;
    }

    void await_suspend(std::coroutine_handle<>) noexcept {
    }

    [[nodiscard]] CancellationToken await_resume() const noexcept {
        return getScheduler()->getCancellationTokenSource().getToken();
    }
};

template<typename T = void>
class CoroTask final {
public:
    template<typename PromiseType>
    using PromiseBase = std::conditional_t<std::is_void_v<T>, PromiseVoid<PromiseType>, PromiseValue<T, PromiseType>>;

    struct promise_type final : PromiseBase<promise_type> {
        CoroTask get_return_object() {
            return CoroTask{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
    };

    struct CoroTaskAwaiter final {
        explicit CoroTaskAwaiter(CoroTask &&task_) noexcept :
            task(std::move(task_)) {
        }
        CoroTaskAwaiter(CoroTaskAwaiter &) = delete;

        auto await_resume() {
            auto &promise = task.handle.promise();
            if (promise.exception) {
                std::rethrow_exception(promise.exception);
            }
            if constexpr (!std::is_void_v<T>) {
                return std::move(*promise.value);
            }
        }

        bool await_ready() noexcept {
            return task.handle.done();
        }

        template<typename ParentPromiseT>
        std::coroutine_handle<> await_suspend(const std::coroutine_handle<ParentPromiseT> parent) noexcept {
            task.handle.promise().continuation = parent;
            return task.handle;
        }

        CoroTask task;
    };

    explicit CoroTask(const std::coroutine_handle<promise_type> h) :
        handle(h) {
    }

    CoroTask(CoroTask &&other) noexcept :
        handle(std::exchange(other.handle, nullptr)) {
    }

    CoroTask &operator=(CoroTask &&other) noexcept = delete;

    CoroTask(CoroTask &) = delete;

    ~CoroTask() {
        if (handle == nullptr) {
            return;
        }
        const auto lifecycle = handle.promise().lifecycle.load();
        if (lifecycle == CoroLifecycle::Started && !handle.done()) {
           std::terminate();
        }
        if (lifecycle != CoroLifecycle::Detached) {
            handle.destroy();
        }
    }

    void start(EpollScheduler &scheduler) {
        transition(CoroLifecycle::Created, CoroLifecycle::Started, "start");
        handle.promise().setScheduler(&scheduler);
        handle.resume();
        if (handle.done()) {
            if (const auto exception = handle.promise().exception) {
                std::rethrow_exception(exception);
            }
        }
    }

    void startDetached(EpollScheduler &scheduler) {
        transition(CoroLifecycle::Created, CoroLifecycle::Detached, "startDetached");
        handle.promise().setScheduler(&scheduler);
        const auto coro = std::exchange(handle, nullptr);
        try {
            scheduler.registerDetached(coro);
            coro.resume();
        } catch (...) {
            scheduler.unregisterDetached(coro);
            coro.destroy();
            throw;
        }
    }

    auto operator co_await() && {
        transition(CoroLifecycle::Created, CoroLifecycle::Awaited, "co_await");
        return CoroTaskAwaiter{std::move(*this)};
    }

    void setScheduler(EpollScheduler *s) noexcept {
        if (handle != nullptr) {
            handle.promise().setScheduler(s);
        }
    }

private:
    void transition(CoroLifecycle expected, const CoroLifecycle desired, const char *operation) {
        if (handle == nullptr) {
            throw std::logic_error(std::string(operation) + ": empty coroutine task");
        }
        if (!handle.promise().lifecycle.compare_exchange_strong(expected, desired)) {
            throw std::logic_error(std::string(operation) + ": coroutine task already consumed");
        }
    }

    std::coroutine_handle<promise_type> handle;
};

#endif // PROXY_OVER_SSH_COROTASK_H
