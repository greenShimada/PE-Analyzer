#include <windows.h>
#include <stdlib.h>
#include <cstdio>
#include <stdio.h>
#include "PEB.h"
#include "myHookedF.h"

#pragma region decls
#define _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES 1

const char* DEFAULT_EXT = ".DLL";
const int MY_PAGE_SIZE = 4096;

extern "C" __declspec(dllexport) HMODULE __cdecl GetModuleHandleAReplacement(IN char* szModuleName);
extern "C" __declspec(dllexport) FARPROC __cdecl GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName);
extern "C" __declspec(dllexport) BOOL __cdecl isEqualCStr(IN LPCSTR Str1, IN LPCSTR Str2);
extern "C" __declspec(dllexport) BOOL isEqualCStrWide(IN wchar_t* Str1, IN LPCSTR Str2);
extern "C" __declspec(dllexport) PVOID __cdecl HookIAT(uintptr_t  pTarget, PCSTR lpModuleName, PCSTR lpApiName, PVOID replacement);
extern "C" __declspec(dllexport) void __cdecl RunHook();
extern "C" __declspec(dllexport) void __cdecl EnableDebugConsole();
extern "C" __declspec(dllexport) void __cdecl Hook(uintptr_t  pTarget, HMODULE hModule, PCWSTR lpApiName, PVOID replacement);
extern "C" __declspec(dllexport) BOOL __cdecl PatchIATEntry(uintptr_t  pTarget, PCSTR lpApiName, PIMAGE_IMPORT_DESCRIPTOR pModuleEntry, PVOID replacement);


#pragma endregion

// Função exportada com a assinatura correta para rundll32
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        EnableDebugConsole();
        RunHook();
        break;
    case DLL_PROCESS_DETACH:
      
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void __cdecl EnableDebugConsole() {
    if (AllocConsole()){
        FILE* fpstdout = stdout;
        FILE* fpstderr = stderr;
        freopen_s(&fpstdout, "CONOUT$", "w", stdout);
        freopen_s(&fpstderr, "CONOUT$", "w", stderr);
        SetWindowText(GetConsoleWindow(), L"dll to be injected debug");
    }
}

extern "C" __declspec(dllexport) void __cdecl RunHook() {
    CreateFileWOriginal = (CreateFileW_T)HookIAT((uintptr_t)GetModuleHandleAReplacement(NULL), "Kernel32.dll\0", "CreateFileW", CreateFileWHook);
    ReadFileOriginal = (ReadFile_T)HookIAT((uintptr_t)GetModuleHandleAReplacement(NULL), "Kernel32.dll\0", "ReadFile", ReadFileWHook);
    RegOpenKeyExOriginal = (RegOpenKeyEx_T)HookIAT((uintptr_t)GetModuleHandleAReplacement(NULL), "Advapi32.dll\0", "RegOpenKeyEx", RegOpenKeyExWHook);
    LoadLibraryAOriginal = (LoadLibraryA_T)HookIAT((uintptr_t)GetModuleHandleAReplacement(NULL), "Kernel32.dll\0", "LoadLibraryA", LoadLibraryAWHook);

    if (!LoadLibraryAOriginal) printf("\n[ERR] LoadLibraryA not found\n");
    if (!CreateFileWOriginal) printf("\n[ERR] CreateFileW not found\n");
    if (!ReadFileOriginal) printf("\n[ERR] ReadFile not found\n");
    if (!RegOpenKeyExOriginal) printf("\n[ERR] RegOpenKey not found\n");
}

extern "C" __declspec(dllexport) PVOID HookIAT(uintptr_t pTarget, PCSTR lpModuleName, PCSTR lpApiName, PVOID replacement) {
    printf("[*] Hook on %s started\n", lpApiName);
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pTarget;
    PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)(pTarget + pImgDosHdr->e_lfanew);

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY impDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    PIMAGE_IMPORT_DESCRIPTOR pImportAddressTable = (PIMAGE_IMPORT_DESCRIPTOR)(pTarget + impDataDir.VirtualAddress);
    SIZE_T iatSize = impDataDir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    
    BOOL found = FALSE;
    for (SIZE_T i = 0; i < iatSize; i++) {
        char* pModuleName = (CHAR*)(pTarget + pImportAddressTable[i].Name);
        
        if (isEqualCStr(lpModuleName, pModuleName) == TRUE) {
            if(PatchIATEntry(pTarget, lpApiName, &pImportAddressTable[i], replacement))
                found = TRUE;

        }
    }
    if (found) {
        HMODULE hTemp = GetModuleHandleAReplacement((char*)lpModuleName);
       
        if (hTemp)
            return GetProcAddressReplacement(hTemp, lpApiName);
    }
    return NULL;
}

extern "C" __declspec(dllexport) BOOL PatchIATEntry(uintptr_t  pTarget, PCSTR lpApiName, PIMAGE_IMPORT_DESCRIPTOR pModuleEntry, PVOID replacement) {
    PULONG_PTR originalThunk = (PULONG_PTR)(pTarget + pModuleEntry->OriginalFirstThunk);
    PULONG_PTR thunk = (PULONG_PTR)(pTarget + pModuleEntry->FirstThunk);
    
    BOOL found = FALSE;

    while (*originalThunk != NULL) {
      
        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(pTarget + *originalThunk);
    
        if (isEqualCStr(importByName->Name, lpApiName)) {
  
            found = TRUE;
            DWORD protect = 0;
            VirtualProtect(thunk, MY_PAGE_SIZE, PAGE_READWRITE, &protect);
            *thunk = (ULONG_PTR)replacement;
            VirtualProtect(thunk, MY_PAGE_SIZE, protect, &protect);
            break;
        }
        originalThunk++;
        thunk++;
    }
    
    return found;
}

extern "C" __declspec(dllexport) FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName) {
   
    PBYTE pBase = (PBYTE)hModule;
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
  
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY exportDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + exportDataDir.VirtualAddress);

    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PVOID pFunctionAddress = NULL;

    if (lpApiName && (DWORD_PTR)lpApiName <= 0xFFFF) {
        
        WORD ordinal = (WORD)lpApiName & 0xFFFF;
        DWORD base = pImgExportDir->Base;

        if (ordinal < base || (ordinal >= base + pImgExportDir->NumberOfFunctions)) {
         
            return NULL;
        }

        pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[ordinal - base]);
    }
    else {
      
        PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
        PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
            CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

            if (strcmp(lpApiName, pFunctionName) == 0) {
                pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
            }
        }
    }

    if (pFunctionAddress >= (PBYTE)pImgExportDir && pFunctionAddress < (PBYTE)pImgExportDir + exportDataDir.Size) {
        SIZE_T len = strlen((const char*)pFunctionAddress) + 1;

        char* moduleName = (char *)calloc(len, sizeof(char));
        strncpy_s(moduleName, len, (const char *)pFunctionAddress, len);

        char* function = strchr(moduleName, '.');
        *function = 0;
        function++;

        HMODULE hTemp = GetModuleHandleAReplacement(moduleName);
        if (hTemp){
            pFunctionAddress = GetProcAddressReplacement(hTemp, lpApiName);
            free(moduleName);
        }
        else {         
            return NULL;
        }
    }
    printf("\t[+] Found the function! (%s)\n", lpApiName);
    return (FARPROC)pFunctionAddress;
}

extern "C" __declspec(dllexport) HMODULE GetModuleHandleAReplacement(IN char* szModuleName) {
#ifdef _WIN64 
    PPEB pPeb = (PEB*)(__readgsqword(0x60));
#else
    PPEB pPeb = (PEB*)(__readfsqword(0x30)); 
#endif


    if (szModuleName == NULL) {
       
        return (HMODULE) pPeb->ImageBaseAddress;
    }
    
    LPCSTR ext = strchr(szModuleName, '.');


    if (!ext) {

        SIZE_T len = strlen(szModuleName);
        SIZE_T extLen = strlen(DEFAULT_EXT);
        SIZE_T newLen = extLen + len + 1;
        char* temp = (char*)calloc(newLen, sizeof(char));


        if (temp == NULL) {
            printf("ERRO CALLOC");
            return NULL;
        }

        errno_t err = strncpy_s(temp, newLen, szModuleName, len);
        if (err) {
            printf("strncpy_s falhou");
            return NULL;
        }

        err = strncat_s(temp, newLen, DEFAULT_EXT, extLen);
        if (err) {
            printf("strncat_s falhou");
            return NULL;
        }
        szModuleName = temp;
    }
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pLdr->InMemoryOrderModuleList.Flink;
    _LIST_ENTRY* f = pPeb->Ldr->InLoadOrderModuleList.Flink;

    HMODULE hModule = NULL;

    while (pDte) {
        PLDR_DATA_TABLE_ENTRY dataEntry = CONTAINING_RECORD(f, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (dataEntry->BaseDllName.Length > 0) {

            if (isEqualCStrWide((dataEntry->BaseDllName.Buffer), szModuleName)) {
                wprintf(L"\t[-] Found the DLL! (%ls)\n", dataEntry->BaseDllName.Buffer);
                hModule = (HMODULE)dataEntry->DllBase;
               
                break;
            }
        }
        f = dataEntry->InLoadOrderLinks.Flink;
    }
    if (!ext) {
        free(szModuleName);
    }

    return (HMODULE)hModule;
}

extern "C" __declspec(dllexport) BOOL isEqualCStrWide(IN wchar_t *Str1, IN LPCSTR Str2) {
    WCHAR lStr1[MAX_PATH];
    WCHAR lStr2[MAX_PATH];
    int len1 = wcslen(Str1);
    int len2 = strlen(Str2);
 
    if (len1 >= MAX_PATH || len2 >= MAX_PATH) return FALSE;

    for (int i = 0; i < len1; i++) {
        lStr1[i] = (WCHAR)tolower(Str1[i]);
    }
    lStr1[len1] = L'\0';  

    for (int j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower((unsigned char)Str2[j]);
    }
    lStr2[len2] = L'\0';  
    
    //wprintf(L"Comparando %s com %s", lStr1, lStr2);
    if (lstrcmpiW(lStr1, lStr2) == 0) {
        return TRUE;
    }
    return FALSE;
}

extern "C" __declspec(dllexport) BOOL isEqualCStr(IN LPCSTR Str1, IN LPCSTR Str2) {
   
    CHAR lStr1[MAX_PATH], lStr2[MAX_PATH];
    int len1 = strlen(Str1), len2 = strlen(Str2);
    int i;

    if (len1 >= MAX_PATH || len2 >= MAX_PATH) return FALSE;

    for (i = 0; i < len1; i++) {
        lStr1[i] = (CHAR)tolower((unsigned char)Str1[i]);
    }
    lStr1[len1] = '\0'; 

    for (i = 0; i < len2; i++) {
        lStr2[i] = (CHAR)tolower((unsigned char)Str2[i]);
    }
    lStr2[len2] = '\0'; 

    // Imprime as strings comparadas
    //printf("\nComparando %s com %s\n", lStr1, lStr2);

    // Compara as strings
    return strcmp(lStr1, lStr2) == 0;
}
