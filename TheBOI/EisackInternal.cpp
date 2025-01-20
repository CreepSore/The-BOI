#include "EisackInternal.h"

#include "TBOI.h"
#include "ImGui/imgui_impl_opengl3.h"
#include "ImGui/imgui_impl_win32.h"


////////////////////////////////////////////////////////////////////////////////
///  Initialization
////////////////////////////////////////////////////////////////////////////////
#pragma region Initialization
EisackInternal::EisackInternal()
{
    uiData.hookManager = kfw::core::Factory::getDefaultHookManager();
    imguiInitialized = false;
}

void EisackInternal::initialize()
{
    uiData.tps = static_cast<int>(1.0 / TBOI::tickspeed());
    setupHooks();
}
#pragma endregion

////////////////////////////////////////////////////////////////////////////////
///  ImGui
////////////////////////////////////////////////////////////////////////////////
#pragma region ImGui
void EisackInternal::setupImgui(HDC hdc)
{
    imguiInitialized = true;
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGui_ImplWin32_Init(WindowFromDC(hdc));
    ImGui_ImplOpenGL3_Init();
}

void EisackInternal::renderImGuiHud()
{
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

    ImGui::Text(THE_BOI_VERSON);

    ImGui::End();
}

void EisackInternal::renderImGuiMenuHomePage()
{
    ImGui::BeginChild("Home");

    if (ImGui::Button("Unload"))
    {
        shutdown();
    }

    if (ImGui::SliderInt("TPS", &uiData.tps, 60, 1000))
    {
        TBOI::tickspeedSet(1.0 / uiData.tps);
    }

    ImGui::EndChild();
}

void EisackInternal::renderImGuiMenuDebugPage()
{
    if(!ImGui::BeginTabBar("Debug", ImGuiTabBarFlags_DrawSelectedOverline))
    {
        return;
    }

    if(ImGui::BeginTabItem("Hooks"))
    {
        if (ImGui::BeginTable(
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

            for (size_t i = 0; i < size; i++)
            {
                kfw::core::HookData* hook = uiData.hookManager->hooks->at(i);

                ImGui::PushID(hook->hrIdentifier.data());
                ImGui::TableNextColumn();

                ImGui::BeginDisabled();
                ImGui::Checkbox("", &hook->bIsHooked);
                ImGui::EndDisabled();

                ImGui::TableNextColumn();
                ImGui::Text(hook->hrIdentifier.data());

                ImGui::TableNextColumn();
                ImGui::Text(toHexString(reinterpret_cast<DWORD>(hook->vpToHook)).data());

                ImGui::TableNextColumn();
                ImGui::Text(toHexString(reinterpret_cast<DWORD>(hook->vpHookedFunc)).data());

                ImGui::TableNextColumn();
                ImGui::Text(toHexString(reinterpret_cast<DWORD>(hook->originalFunction)).data());

                ImGui::TableNextColumn();
                ImGui::PushID("(Un)Hook");

                std::string toggleHookText;

                if (hook->bIsHooked)
                {
                    toggleHookText = "Unhook";
                }
                else
                {
                    toggleHookText = "Hook";
                }

                if (ImGui::Button(toggleHookText.data()))
                {
                    if (hook->bIsHooked)
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

    if(ImGui::BeginTabItem("NtSetInformationThread"))
    {
        if (ImGui::BeginTable(
            "Calls",
            6,
            ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_ScrollY,
            ImGui::GetContentRegionAvail()
        ))
        {
            ImGui::TableSetupColumn("Handle", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupColumn("TIC", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupColumn("Value (hex)", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupColumn("Value (signed)", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupColumn("Value (unsigned)", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupScrollFreeze(6, 1);
            ImGui::TableHeadersRow();

            auto size = uiData.ntSetInformationThreadParameters.size();

            for (size_t i = 0; i < size; i++)
            {
                NtSetInformationThreadParameters param = uiData.ntSetInformationThreadParameters.at(i);

                ImVec4 color = ImGui::GetStyleColorVec4(ImGuiCol_Text);

                if (param.threadInformationClass == _THREADINFOCLASS::ThreadHideFromDebugger)
                {
                    color = ImVec4(1, 0, 0, 1);
                }

                ImGui::PushID(i);
                ImGui::TableNextColumn();

                ImGui::TextColored(color, toHexString(param.threadId, '0', sizeof(uint32_t) * 2).data());
                ImGui::TableNextColumn();

                ImGui::TextColored(color, toHexString(static_cast<DWORD>(param.threadInformationClass), '0', sizeof(uint32_t) * 2).data());
                ImGui::TableNextColumn();

                ImGui::TextColored(color, toHexString(param.value, '0', sizeof(uint32_t) * 2).data());
                ImGui::TableNextColumn();

                ImGui::TextColored(color, std::to_string(static_cast<int32_t>(param.value)).data());
                ImGui::TableNextColumn();

                ImGui::TextColored(color, std::to_string(param.value).data());
                ImGui::TableNextColumn();

                ImGui::TextColored(color, std::to_string(param.size).data());

                ImGui::PopID();
            }

            ImGui::EndTable();
        }

        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("Random"))
    {
        if (!ImGui::BeginTabBar("Random", ImGuiTabBarFlags_DrawSelectedOverline))
        {
            ImGui::EndTabItem();
            return;
        }

        for (const auto& generatedValue : uiData.generatedValues)
        {
            if (generatedValue.second.empty())
            {
                continue;
            }

            if (!ImGui::BeginTabItem(std::to_string(generatedValue.first).data()))
            {
                continue;
            }

            if (!ImGui::BeginTable(
                std::to_string(generatedValue.first).data(),
                1,
                ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_ScrollY,
                ImGui::GetContentRegionAvail()
            ))
            {
                continue;
            }

            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_NoResize);
            ImGui::TableSetupScrollFreeze(1, 1);
            ImGui::TableHeadersRow();

            for (size_t i = 0; i < generatedValue.second.size(); i++)
            {
                ImGui::PushID(i);
                ImGui::TableNextColumn();
                ImGui::Text(std::to_string(generatedValue.second.at(i)).data());
                ImGui::PopID();
            }

            ImGui::EndTable();
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
        ImGui::EndTabItem();
    }

    ImGui::EndTabBar();
}

void EisackInternal::renderImGuiMenuAboutPage()
{
    ImGui::TextLinkOpenURL("https://github.com/creepsore/The-BOI", "https://github.com/creepsore/The-BOI");
}

void EisackInternal::renderImGuiMenu()
{
    if (!uiData.menuVisible)
    {
        return;
    }

    auto viewport = ImGui::GetMainViewport();

    ImGui::SetNextWindowSize(viewport->Size);
    ImGui::SetNextWindowPos(viewport->Pos);
    ImGui::Begin("The BOI - Menu", 0, ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoResize);

    if (ImGui::BeginTabBar("Tabs", ImGuiTabBarFlags_DrawSelectedOverline))
    {
        if (ImGui::BeginTabItem("Home"))
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
#pragma endregion

////////////////////////////////////////////////////////////////////////////////
///  Hooking
////////////////////////////////////////////////////////////////////////////////
#pragma region Hooking
void EisackInternal::setupHooks()
{
    hkGlSwapBuffers = new kfw::core::HookData(
        (void*)kfw::core::Utils::findPattern(GetModuleHandleA("gdi32full.dll"), "\x8b\xff\x55\x8b\xec\x51\x56\x57\x8d\x45\x00\xba\x00\x00\x00\x00\x50\xe8\x00\x00\x00\x00\x8b\xf0\x33\xff\x85\xf6\x74\x00\xff\x75\x00\x8b\xce\xff\x15", "xxxxxxxxxx?x????xx????xxxxxxx?xx?xxxx"),
        EisackInternal::swapBuffers,
        5,
        "hkGlSwapBuffers",
        "SwapBuffers"
    );

    hkGetAsyncKeyState = new kfw::core::HookData(
        (void*)kfw::core::Utils::getFunctionAddress(L"USER32.dll", "GetAsyncKeyState"),
        EisackInternal::getAsyncKeyState,
        5,
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

    hkNtSetInformationThread = new kfw::core::HookData(
        (void*)kfw::core::Utils::getFunctionAddress(L"ntdll.dll", "NtSetInformationThread"),
        EisackInternal::ntSetInformationThread,
        5,
        "hkNtSetInformationThread",
        "NtSetInformationThread"
    );

    hkIsDebuggerPresent = new kfw::core::HookData(
        (void*)kfw::core::Utils::getFunctionAddress(L"kernel32.dll", "IsDebuggerPresent"),
        EisackInternal::isDebuggerPresent,
        6,
        "hkIsDebuggerPresent",
        "IsDebuggerPresent"
    );

    hkRand = new kfw::core::HookData(
        (void*)kfw::core::Utils::getFunctionAddress(L"msvcrt.dll", "rand"),
        EisackInternal::isDebuggerPresent,
        6,
        "hkRand",
        "rand"
    );

    hkSrand = new kfw::core::HookData(
        (void*)kfw::core::Utils::getFunctionAddress(L"msvcrt.dll", "srand"),
        EisackInternal::isDebuggerPresent,
        6,
        "hkSrand",
        "srand"
    );

    auto hookManager = kfw::core::Factory::getDefaultHookManager();
    hookManager->registerHook(hkGlSwapBuffers);
    hookManager->registerHook(hkGetAsyncKeyState);
    hookManager->registerHook(hkWndProc);
    hookManager->registerHook(hkNtSetInformationThread);
    hookManager->registerHook(hkIsDebuggerPresent);

    hookManager->hookAll();
}

BOOL EisackInternal::hookedWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_KEYDOWN)
    {
        switch (wParam)
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
    return ((fnWndProc)hkWndProc->originalFunction)(hWnd, msg, wParam, lParam);
}

SHORT EisackInternal::hookedGetAsyncKeyState(int vkey)
{
    return ((fnGetAsyncKeyState)hkGetAsyncKeyState->originalFunction)(vkey);
}

BOOL EisackInternal::hookedSwapBuffers(HDC hdc)
{
    if (!imguiInitialized)
    {
        setupImgui(hdc);
        return ((fnGlSwapBuffers)(hkGlSwapBuffers->originalFunction))(hdc);
    }

    renderImGui();
    return ((fnGlSwapBuffers)(hkGlSwapBuffers->originalFunction))(hdc);
}

NTSTATUS EisackInternal::hookedNtSetInformationThread(HANDLE handle, _THREADINFOCLASS tic, void* ticPtr, unsigned long size)
{
    uiData.ntSetInformationThreadParameters.emplace_back(handle, tic, ticPtr, size);
    return static_cast<fnNtSetInformationThread>(hkNtSetInformationThread->originalFunction)(handle, tic, ticPtr, size);
}

int EisackInternal::hookedRand()
{
    int result = reinterpret_cast<fnRand>(hkRand)();
    uiData.generatedValues[uiData.currentSeed].push_back(result);

    return result;
}

void EisackInternal::hookedSrand(unsigned int seed)
{
    uiData.currentSeed = seed;
    reinterpret_cast<fnSrand>(hkSrand->originalFunction)(seed);
}
#pragma endregion
