#include <atomic>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

#include "CancellationToken.h"
#include "CoroTask.h"

namespace {
    struct Lifetime final {
        explicit Lifetime(std::atomic_int &destructions_) : destructions(destructions_) {}
        ~Lifetime() { destructions.fetch_add(1); }
        std::atomic_int &destructions;
    };

    struct DualSignalAwaiter final : SchedulerAware<EpollScheduler> {
        DualSignalAwaiter(CompletionSignal &first_, CompletionSignal &second_) : first(first_), second(second_) {}
        bool await_ready() const noexcept { return false; }
        void await_suspend(const std::coroutine_handle<> h) {
            handle = h;
            getScheduler()->add(EpollScheduler::PollIn, first.getFd(), h);
            getScheduler()->add(EpollScheduler::PollIn, second.getFd(), h);
        }
        void await_resume() noexcept {
            getScheduler()->remove(first.getFd(), handle);
            getScheduler()->remove(second.getFd(), handle);
            first.drain();
            second.drain();
        }
        CompletionSignal &first;
        CompletionSignal &second;
        std::coroutine_handle<> handle;
    };

    CoroTask<> complete([[maybe_unused]] std::shared_ptr<Lifetime> lifetime = {}) { co_return; }
    CoroTask<> suspend([[maybe_unused]] std::shared_ptr<Lifetime> lifetime) { co_await std::suspend_always{}; }
    CoroTask<> suspendNested([[maybe_unused]] std::shared_ptr<Lifetime> lifetime) {
        co_await suspend(std::move(lifetime));
    }
    CoroTask<> awaitTask(CoroTask<> task) { co_await std::move(task); }
    CoroTask<> awaitTwoSignals(CompletionSignal &first, CompletionSignal &second,
                               std::atomic_int &resumes, CancellationTokenSource &cts) {
        co_await DualSignalAwaiter{first, second};
        resumes.fetch_add(1);
        cts.requestStop();
    }

    CoroTask<> waitForCancellation(std::atomic_int &completions) {
        try {
            co_await TimerAwaiter{std::chrono::hours(1), co_await GetCancellationToken{}};
        } catch (const CancellationTokenException &) {
            completions.fetch_add(1);
        }
    }

    template<typename F>
    bool throwsLogicError(F &&f) {
        try {
            std::forward<F>(f)();
        } catch (const std::logic_error &) {
            return true;
        }
        return false;
    }
}

int main() {
    std::atomic_int completedDestructions = 0;
    {
        CancellationTokenSource cts;
        EpollScheduler scheduler(cts);
        auto task = complete(std::make_shared<Lifetime>(completedDestructions));
        task.startDetached(scheduler);
        if (completedDestructions.load() != 1) return 1;
    }
    if (completedDestructions.load() != 1) return 2;

    std::atomic_int suspendedDestructions = 0;
    {
        CancellationTokenSource cts;
        EpollScheduler scheduler(cts);
        auto task = suspend(std::make_shared<Lifetime>(suspendedDestructions));
        task.startDetached(scheduler);
    }
    if (suspendedDestructions.load() != 1) return 3;

    std::atomic_int nestedDestructions = 0;
    {
        CancellationTokenSource cts;
        EpollScheduler scheduler(cts);
        auto task = suspendNested(std::make_shared<Lifetime>(nestedDestructions));
        task.startDetached(scheduler);
    }
    if (nestedDestructions.load() != 1) return 4;

    {
        CancellationTokenSource cts;
        EpollScheduler scheduler(cts);
        auto task = complete();
        task.start(scheduler);
        if (!throwsLogicError([&] { task.start(scheduler); })) return 5;

        auto parent = awaitTask(std::move(task));
        if (!throwsLogicError([&] { parent.start(scheduler); })) return 6;
    }

    {
        auto task = complete();
        [[maybe_unused]] auto awaiter = std::move(task).operator co_await();
        if (!throwsLogicError([&] { std::move(task).operator co_await(); })) return 7;
    }

    {
        CancellationTokenSource cts;
        EpollScheduler scheduler(cts);
        CompletionSignal first;
        CompletionSignal second;
        std::atomic_int resumes = 0;
        auto task = awaitTwoSignals(first, second, resumes, cts);
        task.startDetached(scheduler);
        first.signal();
        second.signal();
        scheduler.run();
        if (resumes.load() != 1) return 8;
    }

    {
        constexpr size_t taskCount = 16;
        CancellationTokenSource cts;
        EpollScheduler scheduler(cts);
        std::atomic_int completions = 0;
        std::vector<CoroTask<>> roots;
        roots.reserve(taskCount);
        for (size_t i = 0; i < taskCount; ++i) {
            roots.emplace_back(waitForCancellation(completions));
            roots.back().start(scheduler);
        }

        cts.requestStop();
        scheduler.run();
        if (completions.load() != taskCount) return 9;
    }

    return 0;
}
