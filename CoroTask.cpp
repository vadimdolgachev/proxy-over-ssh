//
// Created by vadim on 07.05.2026.
//

#include "CoroTask.h"
#include "Logger.h"

void EpollScheduler::ThreadPool::enqueue(const std::coroutine_handle<> h) {
    {
        std::lock_guard lock(queueMutex);
        queue.push_back(h);
    }
    cv.notify_one();
}

void EpollScheduler::ThreadPool::worker(const std::stop_token &st) {
    while (!st.stop_requested()) {
        std::coroutine_handle<> h;
        {
            std::unique_lock lock(queueMutex);
            if (!cv.wait(lock, st, [&] { return !queue.empty(); })) {
                return;
            }
            h = queue.back();
            queue.pop_back();
        }
        const auto address = h.address();
        if (!h.done()) {
            h.resume();
        }
    }
}

void EpollScheduler::ThreadPool::stopAndWait() {
    for (auto &worker: workers) {
        worker.request_stop();
    }
    for (auto &worker: workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    log_v("ThreadPool: finished\n");
}

EpollScheduler::ThreadPool::ThreadPool(const size_t numThreads) {
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

    threadPool = std::make_unique<ThreadPool>(Constants::THREAD_POOL_SIZE);
    pendingResumes.reserve(16);
}

void EpollScheduler::add(const uint32_t events, const int fd, const std::coroutine_handle<> coro) {
    std::lock_guard lock(schedulerMutex);

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
    wakeupSignal.signal();
}

void EpollScheduler::remove(const int fd, const std::coroutine_handle<> coro) {
    std::lock_guard lock(schedulerMutex);

    const auto it = fdStates.find(fd);
    if (it == fdStates.end()) {
        return;
    }

    auto &coros = it->second.coros;
    const auto coroIt = std::ranges::find_if(coros, [&](const CoroEntry &e) { return e.h == coro; });
    if (coroIt != coros.end()) {
        coros.erase(coroIt);
        updateEpollRegistration(it);
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

                    auto &coros = fdIt->second.coros;
                    std::erase_if(coros, [&](const CoroEntry &e) {
                        if (e.events & occurredEvents) {
                            pendingResumes.push_back(e.h);
                            return true;
                        }
                        return false;
                    });

                    updateEpollRegistration(fdIt);
                }
            }

            std::ranges::sort(pendingResumes);
            pendingResumes.erase(std::ranges::unique(pendingResumes).begin(), pendingResumes.end());

            for (const auto h: pendingResumes) {
                if (!h.done()) {
                    threadPool->enqueue(h);
                }
            }
        }
    }

    threadPool->stopAndWait();
}

const CancellationTokenSource &EpollScheduler::getCancellationTokenSource() const {
    return cts;
}

uint32_t EpollScheduler::calculateRemainingEvents(const FdState &state) {
    uint32_t remaining = 0;
    for (const auto &coro: state.coros) {
        remaining |= coro.events;
    }
    return remaining;
}

void EpollScheduler::updateEpollRegistration(const FdStates::iterator it) {
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
