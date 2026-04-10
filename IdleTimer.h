#ifndef PROXY_OVER_SSH_IDLETIMER_H
#define PROXY_OVER_SSH_IDLETIMER_H

#include <chrono>

#include "Timer.h"
#include "Constants.h"
#include "Logger.h"

class IdleTimer {
public:
    IdleTimer() = default;

    void arm() {
        timer.armSec(Constants::IDLE_TIMEOUT_SEC);
    }

    void drain() {
        timer.drain();
    }

    bool checkIdleTimeout() {
        drain();
        log_v("Closing connection due to idle timeout\n");
        return true;
    }

    int getFd() const {
        return timer.getFd();
    }

private:
    Timer timer;
};

#endif // PROXY_OVER_SSH_IDLETIMER_H
