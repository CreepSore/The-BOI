#pragma once
#include <iostream>
#include <string>
#include <Windows.h>
#include <psapi.h>

class Eisack
{
private:
    const std::string procName = std::string("isaac-ng.exe");

    HANDLE getProcess(const std::string& procName)
    {
        TCHAR processName[255];

        DWORD processes[1024];
        DWORD cbNeeded;
        DWORD procCount;

        if (!EnumProcesses(processes, sizeof(processes), &cbNeeded))
        {
            return 0;
        }

        procCount = cbNeeded / sizeof(DWORD);

        for (int i = 0; i < procCount; i++)
        {
            HANDLE procHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
            if (procHandle == NULL)
            {
                continue;
            }

            HMODULE moduleHandle;
            if (EnumProcessModules(procHandle, &moduleHandle, sizeof(moduleHandle), &cbNeeded))
            {
                GetModuleBaseName(procHandle, moduleHandle, processName, sizeof(processName) / sizeof(TCHAR));

                std::wstring str = std::wstring(processName);
                if (std::string(str.begin(), str.end()) == procName)
                {
                    this->moduleBaseAddress = moduleHandle;

                    CloseHandle(procHandle);
                    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, processes[i]);
                }
            }

            CloseHandle(procHandle);
        }

        return NULL;
    }

    HANDLE hProc = 0;
    HMODULE moduleBaseAddress = 0;

public:
    ~Eisack()
    {
        if(hProc != 0)
        {
            CloseHandle(hProc);
            hProc = 0;
        }
    }

    void patchModDetection() const
    {
        // We do this here because we're faster.
        SIZE_T written;
        int8_t toWrite[] = { '\xEB' };
        DWORD targetAddress = reinterpret_cast<DWORD>(this->moduleBaseAddress) + 0x4CBC37;

        std::cout << "Patching " << std::hex << targetAddress << " with \\xEB (JMP)\n";
        WriteProcessMemory(this->hProc, reinterpret_cast<void*>(targetAddress), toWrite, sizeof(toWrite) / sizeof(int8_t), &written);
        std::cout << "Patched mod detection\n";
    }

    void injectDll(std::string& path) const
    {
        std::cout << "Injecting DLL @[" << path << "]\n";
        path.push_back('\0');

        void* addr = VirtualAllocEx(this->hProc, nullptr, path.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(!addr)
        {
            std::cout << "Allocation failed.\n";
            return;
        }

        SIZE_T written;
        if(!WriteProcessMemory(this->hProc, addr, path.data(), path.size(), &written))
        {
            std::cout << "WPM failed: " << GetLastError();
            return;
        }

        if(written == 0)
        {
            std::cout << "Writing path failed.\n";
            return;
        }

        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        void* loadLibraryA = GetProcAddress(kernel32, "LoadLibraryA");

        if(!loadLibraryA)
        {
            std::cout << "No LoadLibraryA found!\n";
            return;
        }
        

        CreateRemoteThread(
            this->hProc,
            nullptr,
            0,
            static_cast<LPTHREAD_START_ROUTINE>(loadLibraryA),
            addr,
            0,
            nullptr
        );

        std::cout << "Injected DLL\n";
    }

    void init()
    {
        std::cout << "Waiting for isaac-ng.exe ...\n";

        if(hProc != 0)
        {
            CloseHandle(hProc);
            hProc = 0;
        }

        unsigned long tries = 0;
        do
        {
            tries++;
            hProc = getProcess(procName);
        } while (hProc == 0);

        if(tries == 1)
        {
            std::cout << "Game was already running! No Mod-Detection patch applied!\n";
        }
        else
        {
            patchModDetection();
        }

        std::cout << "Found Game [" << procName << "]: [" << std::hex << hProc << "]\n";
    }

};
