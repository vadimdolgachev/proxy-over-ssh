#ifndef PROXY_OVER_SSH_COMPLETIONSIGNAL_H
#define PROXY_OVER_SSH_COMPLETIONSIGNAL_H

#include <sys/eventfd.h>
#include <unistd.h>

#include "FdUtils.h"

class CompletionSignal {
public:
    CompletionSignal() {
        fd.reset(eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC));
    }

    void signal() {
        constexpr uint64_t val = 1;
        [[maybe_unused]] ssize_t r = write(fd.get(), &val, sizeof(val));
    }

    void drain() {
        uint64_t val;
        [[maybe_unused]] ssize_t r = read(fd.get(), &val, sizeof(val));
    }

    [[nodiscard]] int getFd() const {
        return fd.get();
    }

private:
    UniqueFd fd;
};

#endif // PROXY_OVER_SSH_COMPLETIONSIGNAL_H