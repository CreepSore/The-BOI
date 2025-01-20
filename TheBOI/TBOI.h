#pragma once
#include "k-framework.h"

class TBOI
{
public:
    static double* tickspeedPtr()
    {
        return reinterpret_cast<double*>(kfw::core::Utils::getModuleAddress(L"isaac-ng.exe") + 0x734CC8);
    }

    static double tickspeed()
    {
        return *tickspeedPtr();
    }

    static void tickspeedSet(double tickspeed)
    {
        DWORD oldProtect;
        VirtualProtect(tickspeedPtr(), sizeof(double), PAGE_EXECUTE_READWRITE, &oldProtect);
        *tickspeedPtr() = tickspeed;
        VirtualProtect(tickspeedPtr(), sizeof(double), oldProtect, &oldProtect);
    }
};
