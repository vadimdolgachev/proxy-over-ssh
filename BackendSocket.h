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

    virtual CoroTask<size_t> readAsync(std::span<uint8_t> buffer) = 0;

    virtual CoroTask<size_t> writeAsync(std::span<const uint8_t> data) = 0;

    virtual CoroTask<ResultCode> connectAsync(const Endpoint &target) = 0;

    [[nodiscard]] virtual bool isEof() const = 0;

    virtual void close() = 0;

    [[nodiscard]] virtual int fd() const = 0;
};

using BackendSocketPtr = std::shared_ptr<IBackendSocket>;
using BackendFactory = std::function<BackendSocketPtr(const Endpoint &target)>;

#endif //PROXY_OVER_SSH_BACKENDSOCKET_H
