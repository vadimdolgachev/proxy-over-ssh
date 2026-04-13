#ifndef TIMER_H
#define TIMER_H

#include <chrono>
#include <system_error>
#include <cerrno>

#include <sys/timerfd.h>

#include "FdUtils.h"
#include "Constants.h"

class Timer final {
public:
    Timer() {
        fd.reset(timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC));
        if (fd.get() < 0) {
            throw std::system_error(errno, std::system_category(), "timerfd_create failed");
        }
    }

    void arm(const std::chrono::nanoseconds delay) const {
        itimerspec spec{};
        spec.it_value.tv_sec = static_cast<time_t>(delay.count() / Constants::NANOSECONDS_PER_SECOND);
        spec.it_value.tv_nsec = static_cast<long>(delay.count() % Constants::NANOSECONDS_PER_SECOND);
        timerfd_settime(fd.get(), 0, &spec, nullptr);
    }

    void armSec(const int secs) const {
        arm(std::chrono::seconds(secs));
    }

    void drain() const {
        uint64_t val;
        [[maybe_unused]] const ssize_t r = read(fd.get(), &val, sizeof(val));
    }

    [[nodiscard]] int getFd() const noexcept {
        return fd.get();
    }

private:
    UniqueFd fd;
};

#endif // TIMER_H
