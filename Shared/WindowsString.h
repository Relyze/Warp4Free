#pragma once

#include <windows.h>

#include <string_view>

namespace warp4free::windows {

inline bool equals_case_insensitive(std::wstring_view left, std::wstring_view right) {
    if (left.size() != right.size())
        return false;
    return CompareStringOrdinal(left.data(), static_cast<int>(left.size()), right.data(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}

inline bool starts_with_case_insensitive(std::wstring_view text, std::wstring_view prefix) {
    if (prefix.size() > text.size())
        return false;
    return equals_case_insensitive(text.substr(0, prefix.size()), prefix);
}

}
