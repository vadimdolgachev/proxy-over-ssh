#ifndef PROXY_OVER_SSH_IDLETIMER_H
#define PROXY_OVER_SSH_IDLETIMER_H

#include <chrono>

#include "Timer.h"

// NOLINTBEGIN(readability-make-member-function-const)

class IdleTimer final {
public:
    explicit IdleTimer(const std::chrono::seconds timeout_) :
        timeout(timeout_) {
    }

    void arm() noexcept {
        timer.arm(timeout);
    }

    void drain() noexcept {
        timer.drain();
    }

    [[nodiscard]] int getFd() const noexcept {
        return timer.getFd();
    }

private:
    const std::chrono::seconds timeout;
    Timer timer;
};

// NOLINTBEGIN(readability-make-member-function-const)

#endif // PROXY_OVER_SSH_IDLETIMER_H
