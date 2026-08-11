//
// Created by vadim on 19.03.2026.
//

#ifndef PROXY_OVER_SSH_BACKENDSOCKET_H
#define PROXY_OVER_SSH_BACKENDSOCKET_H

#include "CoroTask.h"
#include "Endpoint.h"
#include "Types.h"

#include <span>
#include <memory>
#include <functional>

class IBackendSocket {
public:
    virtual ~IBackendSocket() = default;

    virtual CoroLite::CoroTask<size_t> readAsync(std::span<uint8_t> buffer, CoroLite::CancellationTokenOpt ct) = 0;

    virtual CoroLite::CoroTask<size_t> writeAsync(std::span<const uint8_t> data,
                                                  CoroLite::CancellationTokenOpt ct) = 0;

    virtual CoroLite::CoroTask<ResultCode> connectAsync(const CoroLite::Endpoint &target,
                                                        CoroLite::CancellationTokenOpt ct) = 0;

    [[nodiscard]] virtual bool isEof() const = 0;

    virtual void close() = 0;

    [[nodiscard]] virtual int fd() const = 0;
};

using BackendSocketPtr = std::shared_ptr<IBackendSocket>;
using BackendFactory = std::function<BackendSocketPtr(const CoroLite::Endpoint &target)>;

#endif //PROXY_OVER_SSH_BACKENDSOCKET_H
