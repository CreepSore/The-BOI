#include "Eisack.h"

int main()
{
    std::string dllPath = std::string("D:\\_Dev\\TBOIModBypass\\Debug\\TheBOI.dll");

    Eisack eisack;
    eisack.init();
    eisack.injectDll(dllPath);
}
