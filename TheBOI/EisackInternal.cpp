#include "EisackInternal.h"

#include <Windows.h>
#include <iostream>

#include "ImGui/imgui_impl_opengl3.h"


EisackInternal::EisackInternal()
{
    hkGlSwapBuffers = new kfw::core::HookData(
        (void*)kfw::core::Utils::getFunctionAddress(L"gdi32full.dll", "SwapBuffers"),
        EisackInternal::swapBuffers,
        5,
        "hkGlSwapBuffers",
        "hkGlSwapBuffers"
    );

    hkGetAsyncKeyState = new kfw::core::HookData(
        (void*)(kfw::core::Utils::getModuleAddress(L"gameoverlayrenderer.dll") + 0x84b70),
        EisackInternal::getAsyncKeyState,
        10,
        "hkGetAsyncKeyState",
        "hkGetAsyncKeyState"
    );

    hkWndProc = new kfw::core::HookData(
        (void*)(kfw::core::Utils::getModuleAddress(L"isaac-ng.exe") + 0x61EE40),
        EisackInternal::wndProc,
        6,
        "hkWndProc",
        "hkWndProc"
    );

    imguiInitialized = false;
}

void EisackInternal::setupHooks()
{
    auto hackman = kfw::core::Factory::getDefaultHookManager();
    hackman->registerHook(hkGlSwapBuffers);
    hackman->registerHook(hkGetAsyncKeyState);
    hackman->registerHook(hkWndProc);

    hackman->hookAll();

    Sleep(5000);
}
