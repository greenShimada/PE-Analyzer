#include <windows.h>
#include <stdlib.h>
#include <cstdio>

extern "C" __declspec(dllexport) void __cdecl HelloWorld();
extern "C" __declspec(dllexport) int __cdecl M_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
extern "C" __declspec(dllexport) void __cdecl Hook_MessageBoxA();
    


extern "C" __declspec(dllexport) void __cdecl HelloWorld() {
    MessageBoxA(NULL, "HOOKED", "A", 0);
}

extern "C" __declspec(dllexport) void __cdecl Patch_MessageBoxA() {
    // Essa função vai rodar dentro da thread remotamente e vai alterar o IAT.
    MessageBoxA(NULL, "Entered patch_messageboxA", "A", 1);
}

// Função exportada com a assinatura correta para rundll32
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            printf("DLL Loaded\n");
            break;
        case DLL_PROCESS_DETACH:
            printf("DLL Unloaded\n");
            break;
    }
    return TRUE;
}
