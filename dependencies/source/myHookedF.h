#include <windows.h>
#include <stdio.h>

#pragma once

typedef void (*CreateFileW_T)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef void (*ReadFile_T)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef void (*RegOpenKeyEx_T)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef void (*LoadLibraryA_T)(LPCSTR);


CreateFileW_T CreateFileWOriginal = NULL;
ReadFile_T ReadFileOriginal = NULL;
RegOpenKeyEx_T RegOpenKeyExOriginal = NULL;
LoadLibraryA_T LoadLibraryAOriginal = NULL;


void LoadLibraryAWHook(LPCSTR lpLibFileName) {
    printf("[*] Library loaded! - %s\n", lpLibFileName);
    LoadLibraryAOriginal(lpLibFileName);

}

void RegOpenKeyExWHook(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
) {
    printf("[*] Register openned! Register: %p, Sub Register\n", hKey, lpSubKey);
    RegOpenKeyExOriginal(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

void ReadFileWHook(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
) {
    printf("[*] ReadFile Hooked! Handle: %p \n", hFile);
    LPVOID temp = lpBuffer;
    ReadFileOriginal(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    printf("\nConteudo do buffer: %s", temp);
}


void CreateFileWHook(
    _In_           LPCWSTR                lpFileName,
    _In_           DWORD                  dwDesiredAccess,
    _In_           DWORD                  dwShareMode,
    _In_opt_       LPSECURITY_ATTRIBUTES  lpSecurityAttributes,
    _In_           DWORD                  dwCreationDisposition,
    _In_           DWORD                  dwFlagsAndAttributes,
    _In_opt_       HANDLE                 hTemplateFile)
{
    printf("[*] CreateFileW Hooked! File path: \b%ws\n", lpFileName);
    CreateFileWOriginal(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

