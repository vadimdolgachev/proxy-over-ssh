//
// Created by vadim on 18.04.2026.
//

#ifndef PROXY_OVER_SSH_CANCELLATIONTOKEN_H
#define PROXY_OVER_SSH_CANCELLATIONTOKEN_H

#include <atomic>
#include <memory>
#include <optional>

#include "CompletionSignal.h"

class CancellationToken final {
public:
    CancellationToken(const CancellationToken &) = delete;
    CancellationToken &operator=(const CancellationToken &) = delete;
    CancellationToken(CancellationToken &&) noexcept = default;
    CancellationToken &operator=(CancellationToken &&) noexcept = default;

    [[nodiscard]] bool isStopped() const noexcept;

    [[nodiscard]] int getFd() const noexcept;

    void drain() const noexcept;

private:
    struct State final {
        std::atomic_bool stopped{false};
        CompletionSignal signal;
    };

    std::shared_ptr<State> state;

    explicit CancellationToken(std::shared_ptr<State> s);

    friend class CancellationTokenSource;
};

using CancellationTokenOpt = std::optional<CancellationToken>;

class CancellationTokenSource final {
public:
    CancellationTokenSource();

    [[nodiscard]] CancellationToken getToken() const noexcept;

    void requestStop() noexcept;

private:
    std::shared_ptr<CancellationToken::State> state;
};

#endif // PROXY_OVER_SSH_CANCELLATIONTOKEN_H
