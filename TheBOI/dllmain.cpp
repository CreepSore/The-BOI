// dllmain.cpp : Definiert den Einstiegspunkt für die DLL-Anwendung.

#include <ios>
#include <Windows.h>

#include "EisackInternal.h"

void thread()
{
    kfw::core::Utils::setupConsole();
    EisackInternal::instance()->initialize();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(
            nullptr, 
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(thread), 
            0, 
            0, 
            nullptr
        );
        break;

    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

