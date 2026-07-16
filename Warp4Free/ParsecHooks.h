#pragma once

#include "ParsecRuntime.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace warp4free::parsec {

inline constexpr std::string_view ui_update_frame_pattern = "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 83 EC ?? 48 8B F9";
inline constexpr std::string_view render_main_settings_pattern = "48 89 5C 24 ?? 48 89 74 24 ?? 55 41 54";
inline constexpr std::string_view refresh_account_capabilities_native_pattern = "48 8B C4 48 89 58 ?? 4C 89 48 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D 68";
inline constexpr std::string_view config_clear_layer_value_pattern = "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 8B F1 41 0F B6 F8";
inline constexpr std::size_t permission_pointer_offset = 0x90;
inline constexpr std::size_t permission_record_size = 15;
inline constexpr std::uint8_t permission_grant_value = 0xFF;
inline constexpr std::size_t warp_capability_offset = 327;
inline constexpr unsigned int account_config_layer = 6;

struct ParsecSymbols {
    std::uintptr_t ui_update_frame;
    std::uintptr_t render_main_settings;
    std::uintptr_t refresh_account_capabilities_native;
    std::uintptr_t config_clear_layer_value;
};

struct ConfigLayerValue {
    const char* key;
    std::uint8_t stream;
};

inline constexpr std::array<ConfigLayerValue, 10> warp_account_overrides = {{{"client_decoder_444", 0}, {"client_decoder_444", 1}, {"client_decoder_444", 2}, {"client_enhanced_pen", 0}, {"host_virtual_tablet", 0}, {"host_virtual_monitors", 0}, {"host_privacy_mode", 0}, {"client_wcam_passthrough", 0}, {"host_virtual_camera", 0}, {"client_automatic_displays", 0}}};

using UiUpdateFrame = std::int64_t(__fastcall*)(std::int64_t state, int width, int height, float scale, int flags, std::int64_t ui_state, std::int64_t ui_context, void* output, void* status, std::int64_t items, int* item_count);
using RenderMainSettings = std::int64_t(__fastcall*)(std::int64_t settings_state, std::int64_t ui_context, float width, std::uint8_t* permissions, std::uint8_t reset_scroll);
using RefreshAccountCapabilitiesNative = std::int64_t(__fastcall*)(std::int64_t refresh_state, std::int64_t ui_context, std::int64_t error_state, std::uint8_t* account_record, std::uint8_t* request_state, std::int64_t mode);
using ConfigClearLayerValue = std::uint8_t(__fastcall*)(unsigned int layer, const char* key, std::uint8_t stream);

void install_hooks();

}
