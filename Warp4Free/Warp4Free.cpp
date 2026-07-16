#include <windows.h>

#include "ParsecHooks.h"

static DWORD WINAPI initialize(LPVOID) {
    warp4free::parsec::install_hooks();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    const HANDLE initialization_thread = CreateThread(nullptr, 0, initialize, nullptr, 0, nullptr);
    if (initialization_thread == nullptr)
        return FALSE;

    CloseHandle(initialization_thread);
    return TRUE;
}
