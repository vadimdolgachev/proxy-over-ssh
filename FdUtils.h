#ifndef PROXY_OVER_SSH_FDUTILS_H
#define PROXY_OVER_SSH_FDUTILS_H

#include <unistd.h>
#include <utility>

struct CloseFdFinalizer final {
    void operator()(const int fd) const noexcept {
        close(fd);
    }
};

template<typename Finalizer = CloseFdFinalizer>
class UniqueFdBasic final {
public:
    explicit UniqueFdBasic(const int fd_ = -1) noexcept :
        fd(fd_) {
    }

    UniqueFdBasic(const UniqueFdBasic &) = delete;

    UniqueFdBasic &operator=(const UniqueFdBasic &) = delete;

    UniqueFdBasic(UniqueFdBasic &&other) noexcept :
        fd(other.release()) {
    }

    UniqueFdBasic &operator=(UniqueFdBasic &&other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    void reset(const int newFd) noexcept {
        if (fd == newFd) {
            return;
        }
        if (fd >= 0) {
            Finalizer()(fd);
        }
        fd = newFd;
    }

    [[nodiscard]] int release() noexcept {
        return std::exchange(fd, -1);
    }

    ~UniqueFdBasic() noexcept {
        if (fd >= 0) {
            Finalizer()(fd);
        }
    }

    [[nodiscard]] int get() const noexcept {
        return fd;
    }

private:
    int fd = -1;
};

using UniqueFd = UniqueFdBasic<>;

#endif // PROXY_OVER_SSH_FDUTILS_H
