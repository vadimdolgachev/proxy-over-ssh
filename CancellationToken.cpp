//
// Created by vadim on 18.04.2026.
//

#include "CancellationToken.h"

bool CancellationToken::isStopped() const noexcept {
    return state->stopped.load(std::memory_order_relaxed);
}

int CancellationToken::getFd() const noexcept {
    return state->signal.getFd();
}

void CancellationToken::drain() const noexcept {
    state->signal.drain();
}

CancellationToken::CancellationToken(std::shared_ptr<State> s) :
    state(std::move(s)) {
}

CancellationTokenSource::CancellationTokenSource() :
    state(std::make_shared<CancellationToken::State>()) {
}

CancellationToken CancellationTokenSource::getToken() const noexcept {
    return CancellationToken(state);
}

void CancellationTokenSource::requestStop() noexcept {
    state->stopped.store(true, std::memory_order_relaxed);
    state->signal.signal();
}
