#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS                  0x00000000L
#define STATUS_INFO_LENGTH_MISMATCH     0xC0000004L

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectAllTypesInformation = 3,
    ObjectHandleFlagInformation = 4
} OBJECT_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

extern NTSTATUS __stdcall NtQueryObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

extern NTSTATUS __stdcall NtDuplicateObject(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
);

extern NTSTATUS __stdcall NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Structure to store handle information
typedef struct _HANDLE_INFO {
    USHORT Handle;
    WCHAR Name[MAX_PATH];
    ACCESS_MASK Access;
} HANDLE_INFO, * PHANDLE_INFO;

// Comparison function for qsort
int CompareHandleInfo(const void* a, const void* b) {
    return _wcsicmp(((PHANDLE_INFO)a)->Name, ((PHANDLE_INFO)b)->Name);
}

BOOL EnableDebugPrivilege(VOID) {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL bRet = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
    CloseHandle(hToken);
    return bRet;
}

BOOL GetHandleName(HANDLE hProcess, HANDLE hObject, WCHAR* Buffer, DWORD BufferSize) {
    HANDLE hDuplicate = NULL;
    BOOL success = FALSE;

    if (NT_SUCCESS(NtDuplicateObject(
        hProcess,
        hObject,
        GetCurrentProcess(),
        &hDuplicate,
        0,
        0,
        DUPLICATE_SAME_ACCESS))) {

        ULONG returnLength;
        POBJECT_NAME_INFORMATION nameInfo = NULL;
        ULONG nameInfoSize = 0x1000;

        do {
            nameInfo = (POBJECT_NAME_INFORMATION)malloc(nameInfoSize);
            if (!nameInfo) break;

            NTSTATUS status = NtQueryObject(
                hDuplicate,
                ObjectNameInformation,
                nameInfo,
                nameInfoSize,
                &returnLength
            );

            if (NT_SUCCESS(status)) {
                if (nameInfo->Name.Buffer && nameInfo->Name.Length > 0) {
                    wcsncpy_s(Buffer, BufferSize, nameInfo->Name.Buffer, nameInfo->Name.Length / 2);
                    Buffer[nameInfo->Name.Length / 2] = L'\0';
                    success = TRUE;
                }
                break;
            }

            free(nameInfo);
            nameInfo = NULL;
            nameInfoSize *= 2;
        } while (nameInfoSize <= 0x10000);

        if (nameInfo) free(nameInfo);
        CloseHandle(hDuplicate);
    }

    return success;
}

int main(int argc, const char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <pid> [dbgpriv (1)]\n", argv[0]);
        return EXIT_FAILURE;
    }

    ULONG cbBufSiz = 0x10000;
    DWORD dwPid = strtoul(argv[1], NULL, 0);

    if (argc >= 3 && 1 == atoi(argv[2])) {
        if (!EnableDebugPrivilege()) {
            fprintf(stderr, "[-] EnableDebugPrivilege failed: E%lu\n", GetLastError());
            return EXIT_FAILURE;
        }
    }

    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwPid);
    if (NULL == hProcess) {
        fprintf(stderr, "[-] OpenProcess failed: E%lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    PSYSTEM_HANDLE_INFORMATION pSysHandleInfo = VirtualAlloc(NULL, cbBufSiz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NULL == pSysHandleInfo) {
        fprintf(stderr, "[-] VirtualAlloc failed: %u\n", GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, pSysHandleInfo, cbBufSiz, NULL);
    while (STATUS_INFO_LENGTH_MISMATCH == status) {
        VirtualFree(pSysHandleInfo, 0, MEM_RELEASE);
        cbBufSiz *= 2;
        pSysHandleInfo = VirtualAlloc(NULL, cbBufSiz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (NULL == pSysHandleInfo) {
            fprintf(stderr, "[-] VirtualAlloc failed: %u\n", GetLastError());
            CloseHandle(hProcess);
            return EXIT_FAILURE;
        }
        status = NtQuerySystemInformation(SystemHandleInformation, pSysHandleInfo, cbBufSiz, NULL);
    }

    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] NtQuerySystemInformation failed: 0x%08X\n", status);
        goto _FINAL;
    }

    // Create an array to store handle information
    HANDLE_INFO* handleList = NULL;
    ULONG handleCount = 0;
    ULONG maxHandles = 1000;  // Initial capacity
    handleList = (HANDLE_INFO*)malloc(sizeof(HANDLE_INFO) * maxHandles);

    if (!handleList) {
        fprintf(stderr, "[-] Memory allocation failed\n");
        goto _FINAL;
    }

    printf("[*] Collecting handles for PID %lu:\n\n", dwPid);

    // Collect handle information
    for (ULONG i = 0; i < pSysHandleInfo->HandleCount; i++) {
        if (dwPid == pSysHandleInfo->Handles[i].ProcessId) {
            WCHAR nameBuf[MAX_PATH] = { 0 };
            if (GetHandleName(hProcess, (HANDLE)pSysHandleInfo->Handles[i].Handle, nameBuf, MAX_PATH) && wcslen(nameBuf) > 0) {
                if (handleCount >= maxHandles) {
                    maxHandles *= 2;
                    HANDLE_INFO* newList = (HANDLE_INFO*)realloc(handleList, sizeof(HANDLE_INFO) * maxHandles);
                    if (!newList) {
                        fprintf(stderr, "[-] Memory reallocation failed\n");
                        free(handleList);
                        goto _FINAL;
                    }
                    handleList = newList;
                }

                handleList[handleCount].Handle = pSysHandleInfo->Handles[i].Handle;
                wcscpy_s(handleList[handleCount].Name, MAX_PATH, nameBuf);
                handleList[handleCount].Access = pSysHandleInfo->Handles[i].GrantedAccess;
                handleCount++;
            }
        }
    }

    if (handleCount > 0) {
        // Sort handles alphabetically by name
        qsort(handleList, handleCount, sizeof(HANDLE_INFO), CompareHandleInfo);

        // Print sorted handles
        printf("[*] Named handles sorted alphabetically:\n\n");
        for (ULONG i = 0; i < handleCount; i++) {
            printf("[%3lu] Handle: 0x%04x - %ls\n", i + 1,
                handleList[i].Handle,
                handleList[i].Name);
        }

        printf("\nFound %lu named handles.\n", handleCount);
        printf("Enter the number of the handle to close (1-%lu) or 0 to exit: ", handleCount);

        ULONG choice;
        if (scanf_s("%lu", &choice) == 1 && choice > 0 && choice <= handleCount) {
            choice--; // Convert to 0-based index
            status = NtDuplicateObject(
                hProcess,
                (HANDLE)handleList[choice].Handle,
                NULL,
                NULL,
                0,
                0,
                DUPLICATE_CLOSE_SOURCE
            );

            if (NT_SUCCESS(status)) {
                printf("\n[+] Successfully closed handle 0x%04x (%ls)\n",
                    handleList[choice].Handle,
                    handleList[choice].Name);
            }
            else {
                printf("\n[-] Failed to close handle 0x%04x: 0x%08X\n",
                    handleList[choice].Handle,
                    status);
            }
        }
        else {
            printf("\n[*] Operation cancelled\n");
        }
    }
    else {
        printf("\n[*] No named handles found\n");
    }

    if (handleList) free(handleList);

_FINAL:
    VirtualFree(pSysHandleInfo, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return EXIT_SUCCESS;
}