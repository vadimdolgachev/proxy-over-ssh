//
// Created by vadim on 07.05.2026.
//

#include "CoroTask.h"
#include "Logger.h"

void EpollScheduler::ThreadPool::enqueue(const std::coroutine_handle<> h) {
    {
        std::lock_guard lock(queueMutex);
        if (stopping) {
            throw std::logic_error("Cannot enqueue coroutine while thread pool is stopping");
        }
        queue.push_back(h);
    }
    cv.notify_one();
}

void EpollScheduler::ThreadPool::worker(const std::stop_token &st) {
    while (true) {
        std::coroutine_handle<> h;
        {
            std::unique_lock lock(queueMutex);
            if (!cv.wait(lock, st, [&] { return stopping || !queue.empty(); })) {
                return;
            }
            if (queue.empty()) {
                return;
            }
            h = queue.back();
            queue.pop_back();
        }
        const auto address = h.address();
        if (!h.done()) {
            h.resume();
        }
        scheduler.onResumeFinished(address);
    }
}

void EpollScheduler::ThreadPool::drainAndStop() {
    {
        std::lock_guard lock(queueMutex);
        stopping = true;
    }
    cv.notify_all();
    for (auto &worker: workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    assert(queue.empty());
    log_v("ThreadPool: finished\n");
}

EpollScheduler::ThreadPool::ThreadPool(EpollScheduler &scheduler_, const size_t numThreads) :
    scheduler(scheduler_) {
    workers.reserve(numThreads);
    for (size_t i = 0; i < numThreads; ++i) {
        workers.emplace_back([this](const auto &st) { worker(st); });
    }
}

EpollScheduler::EpollScheduler(const CancellationTokenSource &cts_) :
    epollFd(epoll_create1(EPOLL_CLOEXEC)),
    cts(cts_) {
    if (epollFd.get() < 0) {
        throw std::runtime_error("Epoll creation failed");
    }

    epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = wakeupSignal.getFd();
    if (epoll_ctl(epollFd.get(), EPOLL_CTL_ADD, wakeupSignal.getFd(), &ev) < 0) {
        throw std::runtime_error("Failed to register wakeup fd with epoll");
    }

    threadPool = std::make_unique<ThreadPool>(*this, Constants::THREAD_POOL_SIZE);
    pendingResumes.reserve(16);
}

EpollScheduler::~EpollScheduler() {
    shutdown();
}

void EpollScheduler::registerDetached(const std::coroutine_handle<> coro) {
    if (shutdownComplete.load()) {
        throw std::system_error(errno, std::system_category(), "Scheduler has been shutdown");
    }
    std::lock_guard lock(detachedMutex);
    detachedCoros.push_back(coro);
}

void EpollScheduler::unregisterDetached(const std::coroutine_handle<> coro) noexcept {
    std::lock_guard lock(detachedMutex);
    if (const auto it = std::ranges::find(detachedCoros, coro);
        it != detachedCoros.end()) {
        detachedCoros.erase(it);
    }
}

void EpollScheduler::add(const uint32_t events, int fd, const std::coroutine_handle<> coro) {
    if (shutdownComplete.load()) {
        throw std::system_error(errno, std::system_category(), "Scheduler has been shutdown");
    }
    std::lock_guard lock(schedulerMutex);

    auto it = fdStates.find(fd);
    const bool exists = it != fdStates.end();

    if (!exists) {
        it = fdStates.emplace(fd, FdState{}).first;
    }
    it->second.coros.push_back({events, coro});

    const int op = exists ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;

    epoll_event ev{};
    ev.events = exists ? calculateRemainingEvents(it->second.coros) : events;
    ev.data.fd = fd;

    if (epoll_ctl(epollFd.get(), op, fd, &ev) < 0) {
        it->second.coros.pop_back();
        if (it->second.coros.empty()) {
            fdStates.erase(it);
        }
        throw std::system_error(errno, std::system_category(), "Epoll add/mod failed");
    }

    wakeupSignal.signal();
}

void EpollScheduler::remove(const int fd, const std::coroutine_handle<> coro) {
    std::lock_guard lock(schedulerMutex);

    const auto it = fdStates.find(fd);
    if (it == fdStates.end()) {
        return;
    }

    auto nextCoros = it->second.coros;
    const auto coroIt = std::ranges::find_if(nextCoros,
        [&](const auto &ce) {
            return ce.handle == coro;
        });
    if (coroIt == nextCoros.end()) {
        return;
    }

    nextCoros.erase(coroIt);
    applyEpollRegistration(fd, nextCoros);
    if (nextCoros.empty()) {
        fdStates.erase(it);
    } else {
        it->second.coros.swap(nextCoros);
    }
}

void EpollScheduler::rollbackAdd(const int fd, const std::coroutine_handle<> coro) noexcept {
    std::lock_guard lock(schedulerMutex);

    const auto it = fdStates.find(fd);
    if (it == fdStates.end()) {
        return;
    }

    auto &coros = it->second.coros;
    const auto coroIt = std::ranges::find_if(coros, [&](const auto &entry) {
        return entry.handle == coro;
    });
    if (coroIt == coros.end()) {
        return;
    }

    coros.erase(coroIt);
    try {
        applyEpollRegistration(fd, coros);
    } catch (...) {
        // The in-memory registration is authoritative. A stale kernel event is
        // ignored and removed by the scheduler when it observes no matching state.
    }
    if (coros.empty()) {
        fdStates.erase(it);
    }
}

void EpollScheduler::forceRemoveFd(const int fd) {
    std::lock_guard lock(schedulerMutex);
    fdStates.erase(fd);
    epoll_ctl(epollFd.get(), EPOLL_CTL_DEL, fd, nullptr);
}

void EpollScheduler::run() {
    std::array<epoll_event, Constants::EPOLL_BATCH_SIZE> events = {};
    const auto cancellationToken = getCancellationTokenSource().getToken();

    while (!cancellationToken.isStopped()) {
        if (const int size = epoll_wait(epollFd.get(), events.data(), events.size(), Constants::EPOLL_TIMEOUT_MS);
            size > 0) {
            pendingResumes.clear();
            {
                std::lock_guard lock(schedulerMutex);
                for (size_t i = 0; i < static_cast<size_t>(size); ++i) {
                    const int eventFd = events[i].data.fd;
                    const uint32_t occurredEvents = events[i].events;

                    if (eventFd == wakeupSignal.getFd()) {
                        wakeupSignal.drain();
                        continue;
                    }

                    auto fdIt = fdStates.find(eventFd);
                    if (fdIt == fdStates.end()) {
                        epoll_ctl(epollFd.get(), EPOLL_CTL_DEL, eventFd, nullptr);
                        continue;
                    }

                    collectReadyCoroutines(fdIt, occurredEvents);
                }
            }
            enqueuePendingResumes();
        }
    }

    pendingResumes.clear();
    {
        std::lock_guard lock(schedulerMutex);
        if (const auto cancellationIt = fdStates.find(cancellationToken.getFd());
            cancellationIt != fdStates.end()) {
            collectReadyCoroutines(cancellationIt, PollIn);
        }
    }
    enqueuePendingResumes();

    shutdown();
}

void EpollScheduler::shutdown() noexcept {
    if (shutdownComplete.exchange(true)) {
        return;
    }

    threadPool->drainAndStop();

    {
        std::lock_guard lock(schedulerMutex);
        fdStates.clear();
        pendingResumes.clear();
        scheduledCoros.clear();
    }

    std::vector<std::coroutine_handle<>> suspended;
    {
        std::lock_guard lock(detachedMutex);
        suspended = std::move(detachedCoros);
        detachedCoros.clear();
    }
    for (const auto coro: suspended) {
        if (coro != nullptr) {
            coro.destroy();
        }
    }
}

void EpollScheduler::collectReadyCoroutines(const FdStates::iterator fdIt, const uint32_t occurredEvents) {
    const int fd = fdIt->first;
    const auto &coros = fdIt->second.coros;
    std::vector<CoroEntry> nextCoros;
    std::vector<std::coroutine_handle<>> readyCoros;
    nextCoros.reserve(coros.size());
    readyCoros.reserve(coros.size());

    try {
        for (const auto &entry: coros) {
            if (entry.events & occurredEvents) {
                if (const auto [_, inserted] = scheduledCoros.insert(entry.handle.address()); inserted) {
                    readyCoros.push_back(entry.handle);
                    continue;
                }
            }
            nextCoros.push_back(entry);
        }

        pendingResumes.reserve(pendingResumes.size() + readyCoros.size());
        applyEpollRegistration(fd, nextCoros);
    } catch (...) {
        for (const auto coro: readyCoros) {
            scheduledCoros.erase(coro.address());
        }
        throw;
    }

    pendingResumes.insert(pendingResumes.end(), readyCoros.begin(), readyCoros.end());
    if (nextCoros.empty()) {
        fdStates.erase(fdIt);
    } else {
        fdIt->second.coros.swap(nextCoros);
    }
}

void EpollScheduler::enqueuePendingResumes() {
    if (pendingResumes.empty()) {
        return;
    }
    std::ranges::sort(pendingResumes);
    pendingResumes.erase(std::ranges::unique(pendingResumes).begin(), pendingResumes.end());
    for (const auto coro: pendingResumes) {
        threadPool->enqueue(coro);
    }
}

void EpollScheduler::onResumeFinished(void *const address) {
    std::lock_guard lock(schedulerMutex);
    scheduledCoros.erase(address);
    wakeupSignal.signal();
}

const CancellationTokenSource &EpollScheduler::getCancellationTokenSource() const {
    return cts;
}

uint32_t EpollScheduler::calculateRemainingEvents(const std::vector<CoroEntry> &coros) {
    return std::ranges::fold_left(coros | std::views::transform(&CoroEntry::events), 0u, std::bit_or());
}

void EpollScheduler::applyEpollRegistration(const int fd, const std::vector<CoroEntry> &coros) const {
    if (coros.empty()) {
        while (epoll_ctl(epollFd.get(), EPOLL_CTL_DEL, fd, nullptr) < 0) {
            const int error = errno;
            if (error == EINTR) {
                continue;
            }
            if (error != ENOENT && error != EBADF) {
                throw std::system_error(error, std::system_category(), "Epoll del failed");
            }
            break;
        }
        return;
    }

    epoll_event ev{};
    ev.events = calculateRemainingEvents(coros);
    ev.data.fd = fd;

    int operation = EPOLL_CTL_MOD;
    while (epoll_ctl(epollFd.get(), operation, fd, &ev) < 0) {
        const int error = errno;
        if (error == EINTR) {
            continue;
        }
        if (operation == EPOLL_CTL_MOD && error == ENOENT) {
            operation = EPOLL_CTL_ADD;
            continue;
        }
        throw std::system_error(error, std::system_category(), "Epoll mod/add failed");
    }
}
