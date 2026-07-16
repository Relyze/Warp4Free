#include "ModuleScanner.h"

#include "WindowsString.h"

#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <vector>

namespace warp4free::memory {

using PatternByte = std::optional<std::uint8_t>;

static std::vector<HMODULE> enumerate_module_handles() {
    std::vector<HMODULE> handles(initial_module_capacity);
    const HANDLE process = GetCurrentProcess();

    for (;;) {
        DWORD bytes_needed = 0;
        const DWORD buffer_size = static_cast<DWORD>(handles.size() * sizeof(HMODULE));
        if (!EnumProcessModules(process, handles.data(), buffer_size, &bytes_needed))
            return {};
        if (bytes_needed <= buffer_size) {
            handles.resize(bytes_needed / sizeof(HMODULE));
            return handles;
        }
        handles.resize((bytes_needed + sizeof(HMODULE) - 1) / sizeof(HMODULE));
    }
}

static std::vector<ExecutableRange> find_executable_ranges(const ModuleImage& module) {
    const std::uintptr_t image_base = reinterpret_cast<std::uintptr_t>(module.base);
    if (!module.contains(image_base, sizeof(IMAGE_DOS_HEADER)))
        return {};

    const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(module.base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew < 0)
        return {};

    const std::uintptr_t nt_address = image_base + static_cast<std::uintptr_t>(dos_header->e_lfanew);
    if (!module.contains(nt_address, sizeof(IMAGE_NT_HEADERS64)))
        return {};

    const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt_address);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE || nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return {};

    const std::size_t section_count = nt_headers->FileHeader.NumberOfSections;
    if (section_count > module.size / sizeof(IMAGE_SECTION_HEADER))
        return {};

    const std::uintptr_t section_table = nt_address + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt_headers->FileHeader.SizeOfOptionalHeader;
    const std::size_t section_table_size = section_count * sizeof(IMAGE_SECTION_HEADER);
    if (!module.contains(section_table, section_table_size))
        return {};

    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(section_table);
    std::vector<ExecutableRange> ranges;
    ranges.reserve(section_count);

    for (std::size_t index = 0; index < section_count; ++index) {
        const IMAGE_SECTION_HEADER& section = sections[index];
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            continue;
        const std::size_t section_size = std::max<std::size_t>(section.Misc.VirtualSize, section.SizeOfRawData);
        if (section_size == 0)
            continue;
        const std::uintptr_t section_address = image_base + section.VirtualAddress;
        if (!module.contains(section_address, section_size))
            return {};
        ranges.push_back(ExecutableRange{reinterpret_cast<const std::uint8_t*>(section_address), section_size});
    }

    return ranges;
}

static std::vector<PatternByte> parse_ida_pattern(std::string_view text) {
    std::vector<PatternByte> pattern;
    std::size_t cursor = 0;

    while (cursor < text.size()) {
        cursor = text.find_first_not_of(' ', cursor);
        if (cursor == std::string_view::npos)
            break;

        const std::size_t token_end = text.find(' ', cursor);
        const std::string_view token = text.substr(cursor, token_end - cursor);
        if (token == "?" || token == "??")
            pattern.emplace_back(std::nullopt);
        else {
            unsigned int value = 0;
            const auto [end, error] = std::from_chars(token.data(), token.data() + token.size(), value, 16);
            if (error != std::errc{} || end != token.data() + token.size() || value > std::numeric_limits<std::uint8_t>::max())
                return {};
            pattern.emplace_back(static_cast<std::uint8_t>(value));
        }

        cursor = token_end == std::string_view::npos ? text.size() : token_end + 1;
    }

    return pattern;
}

bool ModuleImage::contains(std::uintptr_t address, std::size_t length) const {
    const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(base);
    if (address < start || length > size)
        return false;
    return address - start <= size - length;
}

std::optional<ModuleImage> find_loaded_module(std::wstring_view prefix) {
    const HANDLE process = GetCurrentProcess();
    const std::vector<HMODULE> handles = enumerate_module_handles();

    for (const HMODULE handle : handles) {
        std::array<wchar_t, MAX_PATH> name_buffer{};
        const DWORD name_length = GetModuleBaseNameW(process, handle, name_buffer.data(), static_cast<DWORD>(name_buffer.size()));
        if (name_length == 0)
            continue;

        const std::wstring_view name(name_buffer.data(), name_length);
        if (!windows::starts_with_case_insensitive(name, prefix))
            continue;

        MODULEINFO module_info{};
        if (!GetModuleInformation(process, handle, &module_info, sizeof(module_info)))
            continue;

        ModuleImage module{static_cast<const std::uint8_t*>(module_info.lpBaseOfDll), static_cast<std::size_t>(module_info.SizeOfImage), std::wstring(name), {}};
        module.executable_ranges = find_executable_ranges(module);
        return module;
    }

    return std::nullopt;
}

std::optional<std::uintptr_t> find_unique_pattern(const ModuleImage& module, std::string_view text) {
    const std::vector<PatternByte> pattern = parse_ida_pattern(text);
    if (pattern.empty())
        return std::nullopt;

    std::optional<std::uintptr_t> match;
    for (const ExecutableRange& range : module.executable_ranges) {
        if (pattern.size() > range.size)
            continue;

        for (std::size_t offset = 0; offset <= range.size - pattern.size(); ++offset) {
            bool matches = true;
            for (std::size_t index = 0; index < pattern.size(); ++index) {
                if (pattern[index].has_value() && range.base[offset + index] != *pattern[index]) {
                    matches = false;
                    break;
                }
            }

            if (!matches)
                continue;
            if (match)
                return std::nullopt;
            match = reinterpret_cast<std::uintptr_t>(range.base + offset);
        }
    }

    return match;
}

}
