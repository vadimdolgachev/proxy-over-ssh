#ifndef BUFFER_H
#define BUFFER_H

#include <vector>
#include <span>

class Buffer {
public:
    explicit Buffer(const size_t size = 0) : storage(size) {
    }

    uint8_t *data() noexcept {
        return storage.data();
    }

    [[nodiscard]] const uint8_t *data() const noexcept {
        return storage.data();
    }

    [[nodiscard]] size_t size() const noexcept {
        return storage.size();
    }

    [[nodiscard]] size_t capacity() const noexcept {
        return storage.capacity();
    }

    std::span<uint8_t> span() noexcept {
        return {storage.data(), storage.size()};
    }

    [[nodiscard]] std::span<const uint8_t> span() const noexcept { return {storage.data(), storage.size()}; }

    std::span<uint8_t> subspan(const size_t offset, const size_t count) noexcept {
        return {storage.data() + offset, count};
    }

    [[nodiscard]] std::span<const uint8_t> subspan(const size_t offset, const size_t count) const noexcept {
        return {storage.data() + offset, count};
    }

    void resize(const size_t newSize) {
        storage.resize(newSize);
    }

    void reserve(const size_t newCapacity) {
        storage.reserve(newCapacity);
    }

    void clear() noexcept {
        storage.clear();
    }

private:
    std::vector<uint8_t> storage;
};

#endif // BUFFER_H
