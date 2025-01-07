#include "EisackInternal.h"

#include <Windows.h>
#include <iostream>

#include "ImGui/imgui_impl_opengl3.h"
#include "ImGui/imgui_internal.h"


EisackInternal::EisackInternal()
{
    hkGlSwapBuffers = new kfw::core::HookData(
        (void*)kfw::core::Utils::findPattern(GetModuleHandleA("gdi32full.dll"), "\x8b\xff\x55\x8b\xec\x51\x56\x57\x8d\x45\x00\xba\x00\x00\x00\x00\x50\xe8\x00\x00\x00\x00\x8b\xf0\x33\xff\x85\xf6\x74\x00\xff\x75\x00\x8b\xce\xff\x15", "xxxxxxxxxx?x????xx????xxxxxxx?xx?xxxx"),
        EisackInternal::swapBuffers,
        5,
        "hkGlSwapBuffers",
        "SwapBuffers"
    );

    hkGetAsyncKeyState = new kfw::core::HookData(
        (void*)kfw::core::Utils::findPattern(GetModuleHandleA("gameoverlayrenderer.dll"), "\x55\x8b\xec\x80\x3d\x00\x00\x00\x00\x00\x74\x00\x8b\x45", "xxxxx?????x?xx"),
        EisackInternal::getAsyncKeyState,
        10,
        "hkGetAsyncKeyState",
        "GetAsyncKeyState"
    );

    hkWndProc = new kfw::core::HookData(
        (void*)kfw::core::Utils::findPattern(GetModuleHandleA("isaac-ng.exe"), "\x55\x8b\xec\x83\xe4\x00\x83\xec\x00\x8b\x45\x00\x56", "xxxxx?xx?xx?x"),
        EisackInternal::wndProc,
        6,
        "hkWndProc",
        "WndProc"
    );

    uiData.hookManager = kfw::core::Factory::getDefaultHookManager();

    imguiInitialized = false;
}

void EisackInternal::setupHooks()
{
    auto hackman = kfw::core::Factory::getDefaultHookManager();
    hackman->registerHook(hkGlSwapBuffers);
    hackman->registerHook(hkGetAsyncKeyState);
    hackman->registerHook(hkWndProc);

    hackman->hookAll();
}

void EisackInternal::renderImGuiHud()
{
    auto renderHook = [](kfw::core::HookData* hk) {
        ImGui::TextColored(ImVec4(0.25, 1, 0.25, 1.0), hk->hrIdentifier.data());

        {
            std::stringstream ss;
            ss << "Address: " << std::hex << reinterpret_cast<DWORD>(hk->vpToHook);
            ImGui::Text(ss.str().data());
        }

        {
            std::stringstream ss;
            ss << "OrigFunction (JMP): " << std::hex << reinterpret_cast<DWORD>(hk->origFunction);
            ImGui::Text(ss.str().data());
        }

        {
            std::stringstream ss;
            ss << "Hook-Function: " << std::hex << static_cast<DWORD>(hk->jmpToAddr);
            ImGui::Text(ss.str().data());
        }

        ImGui::Text("");
    };

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::Begin(
        "HUD",
        0,
        ImGuiWindowFlags_NoTitleBar
        | ImGuiWindowFlags_NoMove
        | ImGuiWindowFlags_NoScrollbar
        | ImGuiWindowFlags_NoResize
        | ImGuiWindowFlags_NoNav
        | ImGuiWindowFlags_NoBackground
        | ImGuiWindowFlags_AlwaysAutoResize
        | ImGuiWindowFlags_NoSavedSettings
    );

    renderHook(hkWndProc);
    renderHook(hkGlSwapBuffers);
    renderHook(hkGetAsyncKeyState);

    ImGui::End();
}

void EisackInternal::renderImGuiMenuHomePage()
{
    ImGui::BeginChild("Home");



    ImGui::EndChild();
}

void EisackInternal::renderImGuiMenuDebugPage()
{
    if (!ImGui::BeginTabBar("Debug", ImGuiTabBarFlags_DrawSelectedOverline))
    {
        return;
    }

    if(ImGui::BeginTabItem("Hooks"))
    {
        if(ImGui::BeginTable(
            "Hooks", 
            6,
            ImGuiTableFlags_SizingFixedFit
        ))
        {
            ImGui::TableSetupColumn("Hooked", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupColumn("Orig Addr", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupColumn("Jmp To Addr", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupColumn("Jmp Back Addr", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupColumn("(Un)Hook", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupScrollFreeze(6, 1);
            ImGui::TableHeadersRow();

            auto size = uiData.hookManager->hooks->size();

            for(size_t i = 0; i < size; i++)
            {
                kfw::core::HookData* hook = uiData.hookManager->hooks->at(i);

                ImGui::PushID(hook->hrIdentifier.data());
                ImGui::TableNextColumn();

                ImGui::BeginDisabled();
                ImGui::Checkbox("", &hook->bIsSettedUp);
                ImGui::EndDisabled();

                ImGui::TableNextColumn();
                ImGui::Text(hook->hrIdentifier.data());

                ImGui::TableNextColumn();
                ImGui::Text(toHexString(reinterpret_cast<DWORD>(hook->vpToHook)).data());

                ImGui::TableNextColumn();
                ImGui::Text(toHexString(reinterpret_cast<DWORD>(hook->vpHookedFunc)).data());

                ImGui::TableNextColumn();
                ImGui::Text(toHexString(reinterpret_cast<DWORD>(hook->origFunction)).data());

                ImGui::TableNextColumn();
                ImGui::PushID("(Un)Hook");

                std::string toggleHookText;

                if(hook->bIsHooked)
                {
                    toggleHookText = "Unhook";
                }
                else
                {
                    toggleHookText = "Hook";
                }

                if (ImGui::Button(toggleHookText.data()))
                {
                    if(hook->bIsHooked)
                    {
                        hook->unhook();
                    }
                    else
                    {
                        hook->hook();
                    }
                }

                ImGui::PopID();
                ImGui::PopID();
            }

            ImGui::EndTable();
        }


        ImGui::EndTabItem();
    }

    ImGui::EndTabBar();
}

void EisackInternal::renderImGuiMenuAboutPage()
{
    
}

void EisackInternal::renderImGuiMenu()
{
    if(!uiData.menuVisible)
    {
        return;
    }

    auto viewport = ImGui::GetMainViewport();

    ImGui::SetNextWindowSize(viewport->Size);
    ImGui::SetNextWindowPos(viewport->Pos);
    ImGui::Begin("The BOI - Menu", 0, ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoResize);

    if(ImGui::BeginTabBar("Tabs", ImGuiTabBarFlags_DrawSelectedOverline))
    {
        if(ImGui::BeginTabItem("Home"))
        {
            renderImGuiMenuHomePage();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Debug"))
        {
            ImGui::BeginChild("Debug");
            renderImGuiMenuDebugPage();
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("About"))
        {
            renderImGuiMenuAboutPage();
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::End();
}

void EisackInternal::renderImGui()
{
    ImGui_ImplWin32_NewFrame();
    ImGui_ImplOpenGL3_NewFrame();
    ImGui::NewFrame();

    if (uiData.demoWindowVisible)
    {
        ImGui::ShowDemoWindow();
    }

    renderImGuiHud();
    renderImGuiMenu();

    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
}

BOOL EisackInternal::hookedWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_KEYDOWN)
    {
        switch(wParam)
        {
        case VK_HOME:
            uiData.demoWindowVisible = !uiData.demoWindowVisible;
            break;

        case VK_INSERT:
            uiData.menuVisible = !uiData.menuVisible;
            break;

        default:
            break;
        }
    }

    ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam);
    return ((fnWndProc)hkWndProc->origFunction)(hWnd, msg, wParam, lParam);
}

SHORT EisackInternal::hookedGetAsyncKeyState(int vkey)
{
    return ((fnGetAsyncKeyState)hkGetAsyncKeyState->origFunction)(vkey);
}

BOOL EisackInternal::hookedSwapBuffers(HDC hdc)
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

    renderImGui();
    return ((fnGlSwapBuffers)(hkGlSwapBuffers->origFunction))(hdc);
}
