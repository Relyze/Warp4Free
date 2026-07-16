#include "ParsecHooks.h"

#include "ModuleScanner.h"

#include <windows.h>

#include <MinHook.h>

#include <atomic>
#include <cstring>
#include <optional>
#include <string>

namespace warp4free::parsec {

struct HookState {
    UiUpdateFrame original_ui_update_frame = nullptr;
    RenderMainSettings original_render_main_settings = nullptr;
    RefreshAccountCapabilitiesNative original_refresh_account_capabilities_native = nullptr;
    ConfigClearLayerValue config_clear_layer_value = nullptr;
    std::atomic_bool stale_account_overrides_cleared = false;
};

static HookState hook_state;

static void show_error(const wchar_t* message) {
    MessageBoxW(nullptr, message, L"Warp4Free Error", MB_OK | MB_ICONERROR);
}

static void show_minhook_error(const wchar_t* operation, MH_STATUS status) {
    const std::wstring message = std::wstring(operation) + L" failed with MinHook status " + std::to_wstring(static_cast<int>(status)) + L".";
    show_error(message.c_str());
}

static std::optional<ParsecSymbols> resolve_parsec_symbols(const memory::ModuleImage& module) {
    const auto ui_update_frame = memory::find_unique_pattern(module, ui_update_frame_pattern);
    if (!ui_update_frame)
        return std::nullopt;

    const auto render_main_settings = memory::find_unique_pattern(module, render_main_settings_pattern);
    if (!render_main_settings)
        return std::nullopt;

    const auto refresh_account_capabilities_native = memory::find_unique_pattern(module, refresh_account_capabilities_native_pattern);
    if (!refresh_account_capabilities_native)
        return std::nullopt;

    const auto config_clear_layer_value = memory::find_unique_pattern(module, config_clear_layer_value_pattern);
    if (!config_clear_layer_value)
        return std::nullopt;

    return ParsecSymbols{*ui_update_frame, *render_main_settings, *refresh_account_capabilities_native, *config_clear_layer_value};
}

static std::optional<ParsecSymbols> find_loaded_parsec_symbols() {
    const auto module = memory::find_loaded_module(module_prefix);
    if (!module) {
        const std::wstring message = L"Could not find a loaded module whose name begins with " + std::wstring(module_prefix) + L".";
        show_error(message.c_str());
        return std::nullopt;
    }

    const auto symbols = resolve_parsec_symbols(*module);
    if (!symbols) {
        const std::wstring message = L"Required signatures were not unique in " + module->name + L".";
        show_error(message.c_str());
        return std::nullopt;
    }

    return symbols;
}

static std::uint8_t* get_permission_record(std::int64_t ui_context) {
    if (ui_context == 0)
        return nullptr;

    std::uint8_t* permissions = nullptr;
    const auto* context = reinterpret_cast<const std::uint8_t*>(ui_context);
    std::memcpy(&permissions, context + permission_pointer_offset, sizeof(permissions));
    return permissions;
}

static void grant_warp_permissions(std::uint8_t* permissions) {
    if (permissions != nullptr)
        std::memset(permissions, permission_grant_value, permission_record_size);
}

static void clear_stale_account_overrides() {
    if (hook_state.config_clear_layer_value == nullptr || hook_state.stale_account_overrides_cleared.load(std::memory_order_acquire))
        return;

    bool all_cleared = true;
    for (const ConfigLayerValue& value : warp_account_overrides) {
        if (hook_state.config_clear_layer_value(account_config_layer, value.key, value.stream) == 0)
            all_cleared = false;
    }

    if (all_cleared)
        hook_state.stale_account_overrides_cleared.store(true, std::memory_order_release);
}

static std::int64_t __fastcall ui_update_frame_detour(std::int64_t state, int width, int height, float scale, int flags, std::int64_t ui_state, std::int64_t ui_context, void* output, void* status, std::int64_t items, int* item_count) {
    grant_warp_permissions(get_permission_record(ui_context));
    return hook_state.original_ui_update_frame(state, width, height, scale, flags, ui_state, ui_context, output, status, items, item_count);
}

static std::int64_t __fastcall render_main_settings_detour(std::int64_t settings_state, std::int64_t ui_context, float width, std::uint8_t* permissions, std::uint8_t reset_scroll) {
    grant_warp_permissions(permissions);
    return hook_state.original_render_main_settings(settings_state, ui_context, width, permissions, reset_scroll);
}

static std::int64_t __fastcall refresh_account_capabilities_native_detour(std::int64_t refresh_state, std::int64_t ui_context, std::int64_t error_state, std::uint8_t* account_record, std::uint8_t* request_state, std::int64_t mode) {
    if (account_record == nullptr)
        return hook_state.original_refresh_account_capabilities_native(refresh_state, ui_context, error_state, account_record, request_state, mode);

    // Parsec snapshots this byte into the local flags that create account-layer masks.
    const std::uint8_t original_capability = account_record[warp_capability_offset];
    account_record[warp_capability_offset] = 1;
    const std::int64_t result = hook_state.original_refresh_account_capabilities_native(refresh_state, ui_context, error_state, account_record, request_state, mode);
    account_record[warp_capability_offset] = original_capability;

    if (original_capability == 0)
        clear_stale_account_overrides();
    return result;
}

template <typename Function> static bool create_hook(std::uintptr_t target, LPVOID detour, Function& original, const wchar_t* name) {
    const MH_STATUS status = MH_CreateHook(reinterpret_cast<LPVOID>(target), detour, reinterpret_cast<LPVOID*>(&original));
    if (status == MH_OK)
        return true;

    const std::wstring operation = std::wstring(L"Creating the ") + name + L" hook";
    show_minhook_error(operation.c_str(), status);
    return false;
}

void install_hooks() {
    const auto symbols = find_loaded_parsec_symbols();
    if (!symbols)
        return;

    hook_state.config_clear_layer_value = reinterpret_cast<ConfigClearLayerValue>(symbols->config_clear_layer_value);

    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        show_minhook_error(L"Initializing MinHook", status);
        return;
    }

    if (!create_hook(symbols->ui_update_frame, reinterpret_cast<LPVOID>(ui_update_frame_detour), hook_state.original_ui_update_frame, L"ui_update_frame")
        || !create_hook(symbols->render_main_settings, reinterpret_cast<LPVOID>(render_main_settings_detour), hook_state.original_render_main_settings, L"render_main_settings")
        || !create_hook(symbols->refresh_account_capabilities_native, reinterpret_cast<LPVOID>(refresh_account_capabilities_native_detour), hook_state.original_refresh_account_capabilities_native, L"refresh_account_capabilities_native")) {
        MH_Uninitialize();
        return;
    }

    status = MH_EnableHook(MH_ALL_HOOKS);
    if (status != MH_OK) {
        show_minhook_error(L"Enabling hooks", status);
        MH_Uninitialize();
        return;
    }

    clear_stale_account_overrides();
}

}
