#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace warp4free::memory {

inline constexpr std::size_t initial_module_capacity = 64;

struct ExecutableRange {
    const std::uint8_t* base;
    std::size_t size;
};

struct ModuleImage {
    const std::uint8_t* base;
    std::size_t size;
    std::wstring name;
    std::vector<ExecutableRange> executable_ranges;

    bool contains(std::uintptr_t address, std::size_t length = 1) const;
};

std::optional<ModuleImage> find_loaded_module(std::wstring_view prefix);
std::optional<std::uintptr_t> find_unique_pattern(const ModuleImage& module, std::string_view text);

}
