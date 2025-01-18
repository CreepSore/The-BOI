#pragma once
#include <cstdint>
#include <iostream>

#include <Windows.h>
#include <TlHelp32.h>

#include "k-framework.h"
#include "ImGui/imgui.h"

#define THE_BOI_VERSON "The BOI v1"
#define PATTERN_ADDRESS uint32_t*

class EisackInternal;
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context,
    ThreadGroupInformation,
    ThreadUmsInformation,
    ThreadCounterProfiling,
    ThreadIdealProcessorEx,
    MaxThreadInfoClass
};

typedef NTSTATUS(__stdcall* fnNtSetInformationThread)(HANDLE, _THREADINFOCLASS, void*, unsigned long);

typedef BOOL(__stdcall* fnGlSwapBuffers)(HDC);
typedef SHORT(__stdcall* fnGetAsyncKeyState)(int);
typedef LRESULT(__stdcall* fnWndProc)(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

struct NtSetInformationThreadParameters
{
    HANDLE handle;
    _THREADINFOCLASS threadInformationClass;
    void* valuePtr;
    uint32_t value;
    unsigned long size;
    DWORD threadId;

    NtSetInformationThreadParameters(HANDLE handle, _THREADINFOCLASS threadInformationClass, void* valuePtr, unsigned long size)
    {
        threadId = GetThreadId(handle);
        this->handle = handle;
        this->threadInformationClass = threadInformationClass;
        this->valuePtr = valuePtr;

        if(size == 1)
        {
            value = *static_cast<uint8_t*>(valuePtr);
        }
        else if(size == 2)
        {
            value = *static_cast<uint16_t*>(valuePtr);
        }
        else if(size == 4)
        {
            value = *static_cast<uint32_t*>(valuePtr);
        }

        this->size = size;
    }
};

struct UiData
{
    bool demoWindowVisible = false;
    bool menuVisible = false;
    kfw::core::HookManager* hookManager;
    std::vector<NtSetInformationThreadParameters> ntSetInformationThreadParameters;
};

static EisackInternal* eisackInstance = nullptr;
static kfw::core::HookData* hkGlSwapBuffers = nullptr;
static kfw::core::HookData* hkGetAsyncKeyState = nullptr;
static kfw::core::HookData* hkWndProc = nullptr;
static kfw::core::HookData* hkNtSetInformationThread = nullptr;
static kfw::core::HookData* hkIsDebuggerPresent = nullptr;

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
    void setupHooks();
    void setupImgui(HDC hdc);
    void renderImGuiHud();
    void renderImGuiMenuHomePage();
    void renderImGuiMenuDebugPage();
    void renderImGuiMenuAboutPage();
    void renderImGuiMenu();
    void renderImGui();

    BOOL __stdcall hookedWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    SHORT __stdcall hookedGetAsyncKeyState(int vkey);
    BOOL __stdcall hookedSwapBuffers(HDC hdc);
    NTSTATUS __stdcall hookedNtSetInformationThread(HANDLE handle, _THREADINFOCLASS tic, void* ticPtr, unsigned long size);

public:
    static EisackInternal* instance()
    {
        if (eisackInstance == nullptr)
        {
            eisackInstance = new EisackInternal();
        }

        return eisackInstance;
    }

    UiData uiData;
    EisackInternal();
    void initialize();

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

    static BOOL __stdcall isDebuggerPresent()
    {
        return 0;
    }

    static NTSTATUS __stdcall ntSetInformationThread(HANDLE handle, _THREADINFOCLASS tic, void* ticPtr, unsigned long size)
    {
        return instance()->hookedNtSetInformationThread(handle, tic, ticPtr, size);
    }

    static std::string toHexString(DWORD value, char fill = '\0', uint8_t width = 0, bool right = false)
    {
        std::stringstream ss;

        if(width > 0 && fill != '\0')
        {
            if(right)
            {
                // What the fuck STDLIB
                ss << std::left;
            }
            else
            {
                ss << std::right;
            }

            ss << std::setfill(fill) << std::setw(width);
        }

        ss << std::hex << value;
        return ss.str();
    }

    static void freezeThreads()
    {
        THREADENTRY32 threadEntry;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
        if(snap == INVALID_HANDLE_VALUE)
        {
            return;
        }

        threadEntry.dwSize = sizeof(THREADENTRY32);

        if(!Thread32First(snap, &threadEntry))
        {
            return;
        }

        do
        {
            if(threadEntry.th32ThreadID == GetCurrentThreadId() || threadEntry.th32OwnerProcessID != GetCurrentProcessId())
            {
                continue;
            }

            HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, 0, threadEntry.th32ThreadID);
            SuspendThread(threadHandle);
            CloseHandle(threadHandle);
        } while (Thread32Next(snap, &threadEntry));

        CloseHandle(snap);
    }

    static void shutdown()
    {
        delete instance();
        kfw::core::Factory::cleanup();
        FreeLibrary(0);
    }
};
