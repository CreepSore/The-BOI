#pragma once
#include <cstdint>
#include <iostream>

#include "k-framework.h"
#include "ImGui/imgui.h"
#include "ImGui/imgui_impl_opengl3.h"
#include "ImGui/imgui_impl_win32.h"

#define PATTERN_ADDRESS uint32_t*

class EisackInternal;
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);                // Use ImGui::GetCurrentContext()

typedef BOOL(__stdcall* fnGlSwapBuffers)(HDC);
typedef SHORT(__stdcall* fnGetAsyncKeyState)(int);
typedef LRESULT(__stdcall* fnWndProc)(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

struct UiData
{
    bool demoWindowVisible = false;
    bool menuVisible = false;
    kfw::core::HookManager* hookManager;
};

static EisackInternal* eisackInstance = nullptr;
static kfw::core::HookData* hkGlSwapBuffers;
static kfw::core::HookData* hkGetAsyncKeyState;
static kfw::core::HookData* hkWndProc;
static bool imguiInitialized;

struct Pattern
{
    const char* moduleName;
    const char* pattern;
    const char* mask;
};

class EisackInternal
{
private:
    kfw::core::Logger logger;

public:
    static EisackInternal* instance()
    {
        if (eisackInstance == nullptr)
        {
            eisackInstance = new EisackInternal();
        }

        return eisackInstance;
    }

    static BOOL __stdcall wndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        return instance()->hookedWndProc(hWnd, msg, wParam, lParam);
    }

    static SHORT __stdcall getAsyncKeyState(int vkey)
    {
        return instance()->hookedGetAsyncKeyState(vkey);
    }

    static BOOL __stdcall swapBuffers(HDC hdc)
    {
        return instance()->hookedSwapBuffers(hdc);
    }

    UiData uiData;
    EisackInternal();

    void setupHooks();
    void renderImGuiHud();
    void renderImGuiMenuHomePage();
    void renderImGuiMenuDebugPage();
    void renderImGuiMenuAboutPage();
    void renderImGuiMenu();
    void renderImGui();

    BOOL __stdcall hookedWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    SHORT __stdcall hookedGetAsyncKeyState(int vkey);
    BOOL __stdcall hookedSwapBuffers(HDC hdc);

    static std::string toHexString(DWORD value)
    {
        std::stringstream ss;
        ss << std::hex << value;
        return ss.str();
    }
};
