#include <stdio.h>
#include <windows.h>
#include <psapi.h>

typedef struct _PE {
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
}PE;



__declspec(dllexport) int InjectDLL(const char* pathdll, const char* exe_name);
__declspec(dllexport) int ErrorMsg(const char* msg);
__declspec(dllexport) int DebugValue(const char* msg);
__declspec(dllexport) BOOL InitializeSuspendedProcess(PROCESS_INFORMATION* processInformation, const char* exe_name);
__declspec(dllexport) void ResumeMainThread(PROCESS_INFORMATION* processInformation);
__declspec(dllexport) BOOL FillPEStructure(HANDLE hProcess, IMAGE_DOS_HEADER* dosHeader, IMAGE_NT_HEADERS* ntHeaders);
__declspec(dllexport) uintptr_t GetBaseAddress(DWORD processId, const wchar_t* moduleName);


__declspec(dllexport) int DebugValue(const char* msg) {
    MessageBoxA(NULL, msg, "Var value", 0);
}

__declspec(dllexport) int ErrorMsg(const char* msg) {
    MessageBoxA(NULL, msg, "Error", 0);
}

__declspec(dllexport) void ResumeMainThread(PROCESS_INFORMATION * processInformation) {
    ResumeThread(processInformation->hThread);
}

__declspec(dllexport) BOOL InitializeSuspendedProcess(PROCESS_INFORMATION* processInformation, const char* exe_name) {
    STARTUPINFO startupInfo = { 0 };
    PROCESS_INFORMATION temp = { 0 };

    if (!CreateProcessA(exe_name, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &temp)) {
        DWORD error = GetLastError();
        char errorMessage[512];

        // Formata a mensagem de erro
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            0,
            errorMessage,
            sizeof(errorMessage),
            NULL
        );

        // Exibe a mensagem de erro
        ErrorMsg(errorMessage);
        return FALSE;

    }
    *processInformation = temp;
    return TRUE;

}

__declspec(dllexport) int InjectDLL(const char* pathdll, const char* exe_name, PROCESS_INFORMATION *processInformation) {

    int nLength = strlen(pathdll) + 1;
    LPVOID lpRemoteString = VirtualAllocEx(processInformation->hProcess, NULL, nLength, MEM_COMMIT, PAGE_READWRITE);

    if (!lpRemoteString) {
        DWORD error = GetLastError();
        char errorMessage[512];

        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            0,
            errorMessage,
            sizeof(errorMessage),
            NULL
        );

        ErrorMsg(errorMessage);
        CloseHandle(processInformation->hProcess);
        return 2;
    }

    if (!WriteProcessMemory(processInformation->hProcess, lpRemoteString, pathdll, nLength, NULL)) {
        DWORD error = GetLastError();
        char errorMessage[512];

        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            0,
            errorMessage,
            sizeof(errorMessage),
            NULL
        );

        ErrorMsg(errorMessage);
        VirtualFreeEx(processInformation->hProcess, lpRemoteString, 0, MEM_RELEASE);
        CloseHandle(processInformation->hProcess);
        return 3;
    }

    LPVOID lpLoadLibraryA = GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(processInformation->hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)lpLoadLibraryA, lpRemoteString, 0, NULL);

    if (!hThread) {
        DWORD error = GetLastError();
        char errorMessage[512];

        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            0,
            errorMessage,
            sizeof(errorMessage),
            NULL
        );

        ErrorMsg(errorMessage);
        VirtualFreeEx(processInformation->hProcess, lpRemoteString, 0, MEM_RELEASE);
        CloseHandle(processInformation->hProcess);
        return 4;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 10;
}







