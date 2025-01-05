#pragma once
#include <cstdint>
#include <iostream>

#include "k-framework.h"
#include "ImGui/imgui.h"
#include "ImGui/imgui_impl_opengl3.h"
#include "ImGui/imgui_impl_win32.h"

#define PATTERN_ADDRESS uint32_t*

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);                // Use ImGui::GetCurrentContext()

typedef BOOL(__stdcall* fnGlSwapBuffers)(HDC);
typedef SHORT(__stdcall* fnGetAsyncKeyState)(int);
typedef LRESULT(__stdcall* fnWndProc)(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

struct UiData
{
    bool demoWindowVisible = false;
};

static kfw::core::HookData* hkGlSwapBuffers;
static kfw::core::HookData* hkGetAsyncKeyState;
static kfw::core::HookData* hkWndProc;
static bool imguiInitialized;
static UiData uiData;

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
    EisackInternal();

    void setupHooks();

    static void renderImgui()
    {
        ImGui_ImplWin32_NewFrame();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui::NewFrame();

        if(uiData.demoWindowVisible)
        {
            ImGui::ShowDemoWindow();
        }

        ImGui::Render();
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    }

    static BOOL __stdcall wndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        if(msg == WM_KEYDOWN)
        {
            if(wParam == VK_INSERT)
            {
                uiData.demoWindowVisible = !uiData.demoWindowVisible;
            }
        }

        ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam);
        return ((fnWndProc)hkWndProc->origFunction)(hWnd, msg, wParam, lParam);
    }

    static SHORT __stdcall getAsyncKeyState(int vkey)
    {
        SHORT result = ((fnGetAsyncKeyState)hkGetAsyncKeyState->origFunction)(vkey);

        return result;
    }

    static BOOL __stdcall swapBuffers(HDC hdc)
    {
        if (!imguiInitialized)
        {
            imguiInitialized = true;
            IMGUI_CHECKVERSION();
            ImGui::CreateContext();

            ImGui_ImplWin32_Init(WindowFromDC(hdc));
            ImGui_ImplOpenGL3_Init();
            return ((fnGlSwapBuffers)(hkGlSwapBuffers->origFunction))(hdc);
        }

        renderImgui();
        return ((fnGlSwapBuffers)(hkGlSwapBuffers->origFunction))(hdc);
    }
};
