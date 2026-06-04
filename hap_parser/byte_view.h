#pragma once

#include <cstdint>
#include <optional>
#include <vector>

/// Lightweight read-only byte buffer with little-endian multi-byte readers.
/// All offsets are absolute. Returns std::nullopt on out-of-range access.
class ByteView {
public:
    explicit ByteView(std::vector<std::uint8_t> bytes) : bytes_(std::move(bytes)) {}

    std::int64_t size() const { return static_cast<std::int64_t>(bytes_.size()); }

    const std::vector<std::uint8_t>& data() const { return bytes_; }

    bool canRead(std::int64_t offset, std::int64_t length) const {
        return offset >= 0 && length >= 0 &&
               offset <= size() && length <= size() - offset;
    }

    std::optional<std::uint16_t> readU16(std::int64_t offset) const {
        if (!canRead(offset, 2)) return std::nullopt;
        return static_cast<std::uint16_t>(bytes_[offset]) |
               (static_cast<std::uint16_t>(bytes_[offset + 1]) << 8);
    }

    std::optional<std::uint32_t> readU32(std::int64_t offset) const {
        if (!canRead(offset, 4)) return std::nullopt;
        return static_cast<std::uint32_t>(bytes_[offset]) |
               (static_cast<std::uint32_t>(bytes_[offset + 1]) << 8) |
               (static_cast<std::uint32_t>(bytes_[offset + 2]) << 16) |
               (static_cast<std::uint32_t>(bytes_[offset + 3]) << 24);
    }

    std::optional<std::int32_t> readI32(std::int64_t offset) const {
        auto value = readU32(offset);
        return value ? std::optional<std::int32_t>(static_cast<std::int32_t>(*value)) : std::nullopt;
    }

    std::optional<std::int64_t> readI64(std::int64_t offset) const {
        if (!canRead(offset, 8)) return std::nullopt;
        std::uint64_t value = 0;
        for (int i = 0; i < 8; ++i)
            value |= static_cast<std::uint64_t>(bytes_[offset + i]) << (8 * i);
        return static_cast<std::int64_t>(value);
    }

    std::optional<std::vector<std::uint8_t>> slice(std::int64_t offset, std::int64_t length) const {
        if (!canRead(offset, length)) return std::nullopt;
        return std::vector<std::uint8_t>(bytes_.begin() + offset, bytes_.begin() + offset + length);
    }

private:
    std::vector<std::uint8_t> bytes_;
};
