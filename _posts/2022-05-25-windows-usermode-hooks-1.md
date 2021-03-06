---
title: Windows usermode hooks - Part 1 - Detection
date: 2022-05-25 14:15:00 +0200
categories: [Redteam, AV/EDR]
tags: [AV/EDR, Malware]
render_with_liquid: false
---

This post will guide you through how to detect usermode hooks in Windows default libraries and APIs, regardless of whether they have been inserted by AV/EDR products or other third-party software.

## Introduction
It is a well-known phenomena that AV/EDR products or software with similar intent, such as anti-cheat products for games, utilize usermode hooking techniques to monitor the usage of vital APIs in the Windows default libraries. A hook can be designed in a variety of ways, but most commonly, they are designed as filters for specific Windows APIs that are commonly used for malicious purposes. By redirecting the flow of a function through a detour function, the parameters of the function can be analysed before deciding whether to continue execution of the original function or whether to deny access to the original function and returning to the caller.

An example of a vital Windows API that most AV/EDR products monitor is the `NtCreateThreadEx` function.

![NtCreateThreadEx1](/assets/img/2022-05-25-windows-usermode-hooks-1/NtCreateThreadEx_1.png)

As can be seen in the illustration above, the function is a wrapper for a syscall into the kernel. This particular function is responsible for spawning a new thread in the context of a process, and is often used by malicious actors to execute buffers containing shellcode. An example of the same API when hooked by an AV/EDR product (in this case, SentinelOne) can be seen below.

![NtCreateThreadEx2](/assets/img/2022-05-25-windows-usermode-hooks-1/NtCreateThreadEx_2.png)

Notice how the first instructions in the function has been replaced with a relative `jmp` instruction that redirects the execution flow into a function located in the `InProcessClient64.dll` library. Here, the SentinelOne library can analyse the parameters of the function in an attempt to evaluate whether the function is being used for malicious purposes. If the library evaluates that the usage is legitimate, they will continue execution of the `NtCreateThreadEx` function. However, if the library evaluates that the usage is malicious, the process will terminate and a security incident event will be raised.

## Enumerating modules

Most AV/EDR products and similar software only target Windows APIs, which can be located by function name in the Windows default libraries, `kernel32.dll`, `kernelbase.dll` and `ntdll.dll`. However, before we can locate these functions, we must first locate their libraries in memory.

When a library is loaded by a Windows process, an entry for the library is inserted into a doubly linked list in the so-called `ProcessEnvironmentBlock` (`PEB`). We can iterate this list as shown below.

```c
PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;

LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
LIST_ENTRY* next = head->Flink;

while (next != head)
{
    LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((PBYTE)next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

    UNICODE_STRING* fullname = &entry->FullDllName;
    UNICODE_STRING* basename = (UNICODE_STRING*)((PBYTE)fullname + sizeof(UNICODE_STRING));

    // Perform enumeration of the individual library here
    // The library address in memory is given by entry->DllBase

    next = next->Flink;
}
```

## Enumerating exports

Once we have located the libraries in memory, we are ready to enumerate their export directory and thereby locate all the functions that they are promoting by name. It is obviously entirely possible to hook unnamed internal functions, but they are harder to locate as they are not being promoted by the libraries themselves, and for that reason, they are usually untouched by AV/EDR products.

In order to enumerate the export directory of the library, we must first understand the PE file format. The PE file format starts with a DOS header, which contains the offset of the subsequent PE header (also called the NT header). Inside the PE header is a `DataDirectory` array, which contains entries that points to various important tables, such as the export table, the import table, the relocation table, etc.

An exported function can be located by two different attributes, either by its name or by its ordinal (function number). We are specifically interested in the export directory of the PE header, which contains a variety of information, including the relative virtual addresses (RVAs) of the following tables:
- The function table, which contains the addresses of all exported functions sorted by their ordinal. 
- The name table, which contains the addresses of all exported names sorted in ascending order.
- The name ordinal table, which contains the ordinals of all exported names sorted in ascending order.

We can consider the name ordinal table a mapping between the name table and the function table. Once we have located an entry in the name table by index, we can access that same index in the name ordinal table to obtain the function ordinal for the given function name. This ordinal can then be used to locate the equivalent entry in the function table by index, and thereby obtaining the address of the named function.

We can perform all of these steps as shown below.

```c
IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)entry->DllBase;
IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((PBYTE)entry->DllBase + dos->e_lfanew);

IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((PBYTE)entry->DllBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

if (exports->AddressOfNames != 0)
{
    WORD* ordinals = (WORD*)((PBYTE)entry->DllBase + exports->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)((PBYTE)entry->DllBase + exports->AddressOfNames);
    DWORD* functions = (DWORD*)((PBYTE)entry->DllBase + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++)
    {
        char* name = (char*)((PBYTE)entry->DllBase + names[i]);
        void* function = (void*)((PBYTE)entry->DllBase + functions[ordinals[i]]);

        // Perform actions using the function name and address
    }
}
```

Interestingly, despite the fact that the export directory is inherently made for exporting functions from Dynamic-Link Libraries (DLLs), it is also possible to export constants and/or objects. Since we are looking for usermode hooks in the code section of a library, we are not interested in data objects or constants, especially since these are subject to modification, and will potentially yield false-positives when we test for hooks by comparing exports to their original variants on disk.

We can guard our enumeration against checking data objects by verifying that all of our target function addresses fall within the code region of the library. The relative virtual address (RVA) and region size of the code section of a library can be found in the PE header as shown below.

```c
if ((PBYTE)function > (PBYTE)entry->DllBase + nt->OptionalHeader.BaseOfCode &&
    (PBYTE)function < (PBYTE)entry->DllBase + nt->OptionalHeader.BaseOfCode + nt->OptionalHeader.SizeOfCode)
{
    // Perform actions using the function name and address
}
```

## Loading KnownDLLs

The next step is to compare the bytes of each exported function against their original unmodified versions. Ideally, we would load the respective library from disk and compare against the bytes at a given offset. Unfortunately, this produces a range of false-positives as the library on disk has not been properly set up and has not had its relocations fixed. Instead of holding on to this crude technique, we will instead analyse how these libraries are initially loaded by the Windows loader and attempt to load a fresh copy using identical functions.

When we load a library using the `LoadLibrary` Windows API, a range of subsequent calls occur. For example, `LoadLibrary` invokes `LoadLibraryEx`, which invokes `LdrLoadDll`, which invokes a deeper nested internal function, and the list goes ever on. If we follow this chain of subsequent invocations, we arrive at a function called `LdrpLoadKnownDll` as seen in the call chain below.

```
LoadLibrary
|-> LoadLibraryEx
|--> LdrLoadDll
|---> LdrpLoadDll
|----> LdrpLoadDllInternal
|-----> LdrpFindOrPrepareLoadingModule
|------> LdrpLoadKnownDll
```

The `LdrpLoadKnownDll` function is responsible for loading KnownDLL libraries, which includes `kernel32.dll` and `kernelbase.dll`. The functionality of the `LdrpLoadKnownDll` function can be seen below.

![LdrpLoadKnownDll](/assets/img/2022-05-25-windows-usermode-hooks-1/LdrpLoadKnownDll.png)

The `LdrpLoadKnownDll` function appears to obtain a section handle to a KnownDLL library by invoking `LdrpFindKnownDll`, and then maps the library into memory by passing the section handle to `LdrpMapDllWithSectionHandle`. Let us take a look at how this section handle is obtained in the `LdrpFindKnownDll` function.

![LdrpFindKnownDll](/assets/img/2022-05-25-windows-usermode-hooks-1/LdrpFindKnownDll.png)

The `LdrpFindKnownDll` function obtains a section handle to a target KnownDLL library by invoking the `NtOpenSection` API with an `OBJECT_ATTRIBUTES` object whose `RootDirectory` attribute is set using an internal `LdrpKnownDllDirectoryHandle` object. Let us take a look at how this section handle is used to map the library into memory in the `LdrpMapDllWithSectionHandle` function.

![LdrpMapDllWithSectionHandle](/assets/img/2022-05-25-windows-usermode-hooks-1/LdrpMapDllWithSectionHandle.png)

The `LdrpMapDllWithSectionHandle` function invokes `LdrpMinimalMapModule` to map the library into memory, and then performs a subsequent series of actions to prepare the module for execution, such as populating the Import Address Table (IAT). Let us take a look at how the `LdrpMinimalMapModule` function works internally.

![LdrpMinimalMapModule](/assets/img/2022-05-25-windows-usermode-hooks-1/LdrpMinimalMapModule.png)

The `LdrpMinimalMapModule` function map the library into memory by invoking the `NtMapViewOfSection` API with the section handle previously obtained from the `NtOpenSection` API call in the `LdrpFindKnownDll` function. 

We should be able to map our own KnownDLL library into memory by obtaining a section handle for the library using the `NtOpenSection` API and then mapping it into memory using the `NtMapViewOfSection` API. However, in order to do this, we must invoke the `NtOpenSection` API with a correctly configured `RootDirectory` handle similar to that of the internal `LdrpKnownDllDirectoryHandle` object.

In the 64-bit version of `ntdll.dll`, an exported function called `LdrGetKnownDllSectionHandle` does exactly what we are looking for. However, this function does not exist in the 32-bit version of `ntdll.dll` (or atleast the SYSWOW64 version), so we will have to create our own function. Let us take a look at how the `LdrGetKnownDllSectionHandle` object is constructed.

![LdrpInitializeProcess1](/assets/img/2022-05-25-windows-usermode-hooks-1/LdrpInitializeProcess_1.png)

The `LdrpInitializeProcess` function constructs the `LdrGetKnownDllSectionHandle` object by invoking the `NtOpenDirectoryObject` API with an `OBJECT_ATTRIBUTES` object whose `ObjectName` attribute is set to a `UNICODE_STRING` object that contains the string `"\KnownDlls"` as shown below.

![LdrpInitializeProcess2](/assets/img/2022-05-25-windows-usermode-hooks-1/LdrpInitializeProcess_2.png)

If we check the same functionality in the SYSWOW64 version of `ntdll.dll`, we observe the same thing, except the `UNICODE_STRING` object contains the string `"\KnownDlls32"` instead.

![LdrpInitializeProcess3](/assets/img/2022-05-25-windows-usermode-hooks-1/LdrpInitializeProcess_3.png)

If we puzzle all of our findings together, we find that we can construct our own `LdrGetKnownDllSectionHandle` function as shown below.

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

## Detecting hooks

We can use the `LdrGetKnownDllSectionHandle` function to obtain a section handle for a KnownDLL library, which we can then map into memory using the `NtMapViewOfSection` API as shown below.

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
    NtMapViewOfSection(hSection, GetCurrentProcess(), &pvBase, 0, 0, NULL, &stSize, ViewUnmap, 0, PAGE_READONLY)

    NtClose(hSection);
}
```

The mapped library should correspond to our target library prior to having hooks installed by AV/EDR products or similar software, and we can use this as a basis for detecting anomalous bytes in exported functions of the original library. 

Since the original library and the mapped library are identical, the offset of exported functions are also the same. In order to locate an exported function in the mapped library, we can obtain its offset by subtracting the base address of the original library, and then add this offset to the base address of the mapped library.

Finally, we need to decide on limitations, such as how many bytes are checked per function. If we decide to check too many bytes per function, we might over-reach into a subsequent function in memory. When this happens, we risk false-positives about a function having been modified, when in fact it is an adjacent function that has been modified.

A relative `jmp` instruction, such as the one used by SentinelOne, consists of a 5 byte sequence. Since hooks are usually inserted at the start of a function, we can assume that a 5 byte limit is adequate for our purposes.

Now that we have gone through every step of the detection phase, we can puzzle our code pieces together and construct the following full sample.

```c
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll")

#define DIRECTORY_QUERY        0x0001
#define DIRECTORY_TRAVERSE    0x0002

typedef enum _SECTION_INHERIT {
    ViewShare=1,
    ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;

extern NTSTATUS NTAPI NtClose(HANDLE Handle);
extern NTSTATUS NTAPI NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
extern NTSTATUS NTAPI NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
extern NTSTATUS NTAPI NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);
extern NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
extern NTSTATUS NTAPI RtlInitUnicodeStringEx(PUNICODE_STRING DestinationString, PCWSTR SourceString);

BOOL LdrGetKnownDllSectionHandle(LPCWSTR DllName, PHANDLE SectionHandle)
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

int main(int argc, char* argv[])
{
    PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;

    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* next = head->Flink;

    while (next != head)
    {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((PBYTE)next - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        UNICODE_STRING* fullname = &entry->FullDllName;
        UNICODE_STRING* basename = (UNICODE_STRING*)((PBYTE)fullname + sizeof(UNICODE_STRING));

        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)entry->DllBase;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((PBYTE)entry->DllBase + dos->e_lfanew);

        IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((PBYTE)entry->DllBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        if (exports->AddressOfNames != 0)
        {
            printf("Checking for hooks in %S\n", basename->Buffer);

            HANDLE section = NULL;

            if (LdrGetKnownDllSectionHandle(basename->Buffer, &section))
            {
                PVOID base = 0;
                SIZE_T size = 0;

                if (NT_SUCCESS(NtMapViewOfSection(section, GetCurrentProcess(), &base, 0, 0, NULL, &size, ViewUnmap, 0, PAGE_READONLY)))
                {
                    WORD* ordinals = (WORD*)((PBYTE)entry->DllBase + exports->AddressOfNameOrdinals);
                    DWORD* names = (DWORD*)((PBYTE)entry->DllBase + exports->AddressOfNames);
                    DWORD* functions = (DWORD*)((PBYTE)entry->DllBase + exports->AddressOfFunctions);

                    for (DWORD i = 0; i < exports->NumberOfNames; i++)
                    {
                        char* name = (char*)((PBYTE)entry->DllBase + names[i]);
                        void* function = (void*)((PBYTE)entry->DllBase + functions[ordinals[i]]);

                        if ((PBYTE)function > (PBYTE)entry->DllBase + nt->OptionalHeader.BaseOfCode &&
                            (PBYTE)function < (PBYTE)entry->DllBase + nt->OptionalHeader.BaseOfCode + nt->OptionalHeader.SizeOfCode)
                        {
                            DWORD offset = (DWORD)((PBYTE)function - (PBYTE)entry->DllBase);
                            void* mapped = (void*)((PBYTE)base + offset);

                            if (memcmp(function, mapped, 5) != 0)
                                printf("Detected hook in %S!%s\n", basename->Buffer, name);
                        }
                    }

                    NtUnmapViewOfSection(GetCurrentProcess(), base);
                }

                NtClose(section);
            }
        }

        next = next->Flink;
    }

    return 0;
}
```

In order to avoid being detected by AV/EDR products when using this tool, our techniques can be taken even further. For a demonstration of this, please visit [the official project on GitHub](https://github.com/st4ckh0und/hook-buster).

## Conclusion

Hope you enjoyed this blog post!

If you have any questions, feel free to reach out to me on [GitHub](https://github.com/st4ckh0und) or [Twitter](https://twitter.com/st4ckh0und).