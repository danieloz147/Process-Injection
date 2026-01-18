# Technical Deep Dive: Process Injection

This document provides in-depth technical information about process injection mechanisms, Windows internals, and implementation details.

**Disclaimer**: This is for educational and authorized security research only. Unauthorized process injection is illegal.

---

## Table of Contents

1. [Windows Internals: Processes and Threads](#windows-internals-processes-and-threads)
2. [Memory Management Architecture](#memory-management-architecture)
3. [Access Tokens and Security Context](#access-tokens-and-security-context)
4. [Process Lifecycle Management](#process-lifecycle-management)
5. [Memory Architecture in Depth](#memory-architecture-in-depth)
6. [Critical Windows APIs](#critical-windows-apis)
7. [Injection Techniques - Deep Dive](#injection-techniques---deep-dive)
8. [Security Considerations](#security-considerations)
9. [Debugging Process Injection](#debugging-process-injection)
10. [Common Pitfalls](#common-pitfalls)
11. [Performance and Optimization](#performance-and-optimization)

---

## Windows Internals: Processes and Threads

### Process Fundamentals

A **process** is a container that encapsulates all resources required for a running program:

- **Program vs. Process**: A program is compiled source code stored in a PE executable file (.exe or .dll). A process is an active instance of that program with its own isolated resources, memory space, and execution context.
- **Resource Isolation**: Each process maintains its own virtual address space, heap, and file handles. Multiple instances of the same program run independently without interfering with one another.

**Process Creation APIs:**

Windows provides three primary APIs for creating new processes:

- **`CreateProcessW`** – Spawns a new process using the same access token as the calling process. This means the new process inherits the security context and privileges of the parent.
- **`CreateProcessAsUserW`** – Spawns a process under an alternate access token. Requires the caller to possess `SeImpersonatePrivilege` or higher privileges.
- **`CreateProcessWithLogonW`** – Creates a new process using plaintext username and password credentials. Useful for interactive logins.

All three APIs ultimately invoke the kernel function **`NtCreateUserProcess`**, which performs the actual process creation at the kernel level.

### Threads: The Execution Unit

A **thread** is the actual execution unit that Windows schedules to run on a CPU:

- **State**: Each thread holds CPU register state and its own call stack (typically 1 MB by default).
- **Minimum Requirement**: Every functional program must have at least one thread executing from the program's entry point.
- **Parallelism**: Multiple threads within a single process enable parallel execution of multiple code paths simultaneously.

**Thread Creation APIs:**

- **`CreateThread`** – Creates a new thread within the current process. The new thread starts executing at a specified function address.
- **`CreateRemoteThread`** – Creates a new thread in a different process. This is a foundational technique for process injection—write code to a target process's memory, then create a remote thread pointing to that code.
- Both APIs internally call **`CreateRemoteThreadEx`** (the extended version), which in turn calls **`NtCreateThreadEx`** at the kernel level.

---

## Memory Management Architecture

### Virtual Memory System

Every process on Windows operates within its own **private virtual address space**:

**Virtual vs. Physical Memory:**

- **Virtual Memory**: The memory space visible to a process. On 32-bit systems, this is typically 4 GB (2 GB user-mode, 2 GB kernel-mode). On 64-bit systems, much larger (typically 128 TB or more per process).
- **Physical Memory**: Actual RAM installed in the computer. The Windows memory manager translates virtual addresses to physical addresses.
- **Paging**: When RAM is exhausted, the memory manager can page (write) data to disk, freeing physical memory for other processes. Paged data is retrieved back into RAM on demand.

**Memory Pages:**

Memory is organized into fixed-size chunks called **pages**:

- **Small Pages**: 4 KB (standard size on x86, x64, and ARM architectures)
- **Large Pages**: 2 MB (x86/x64) or 4 MB (ARM). Used for performance-critical applications.

### Three Memory Management API Families

**1. Virtual Memory APIs (Lowest level)**
- `VirtualAlloc`, `VirtualFree`, `VirtualProtect`, `VirtualAllocEx`, `VirtualFreeEx`
- Operate on entire pages
- Allocations are rounded up to the nearest complete page boundary
- Typical use: Allocating large blocks, protecting memory ranges, injecting code

**2. Heap APIs (Mid level)**
- `HeapAlloc`, `HeapReAlloc`, `HeapFree`, `GetProcessHeap`
- Manage sub-page allocations
- Heap manager sits atop virtual APIs and provides fine-grained allocation
- Typical use: General-purpose memory allocation in applications

**3. Memory-Mapping APIs (File-based)**
- `CreateFileMappingA`, `OpenFileMappingA`, `MapViewOfFile`, `UnmapViewOfFile`
- Map files on disk directly into a process's virtual address space
- Can be shared across multiple processes
- Typical use: Shared memory between processes, memory-mapped I/O

---

## Access Tokens and Security Context

### Access Tokens: The Security Passport

When a process is created, it receives a **primary access token** that defines its security context:

An access token contains:
- **User SID (Security Identifier)** – Uniquely identifies the user
- **Group SIDs** – Lists of groups the user belongs to (e.g., Administrators, Domain Users)
- **User Privileges** – Special rights granted to the user (e.g., SeDebugPrivilege, SeTakeOwnershipPrivilege)
- **Integrity Level** – Indicates the trustworthiness of the process (Low, Medium, High, System)

### Thread Impersonation

By default, new threads inherit the process's primary access token. However:

- Threads can explicitly **impersonate** another user's access token using `ImpersonateLoggedOnUser` or similar APIs
- When a thread impersonates, all work performed by that thread occurs under the impersonated user's security context
- This is a powerful mechanism but also a security risk if misused

### Discretionary Access Control Lists (DACLs)

Every securable object on Windows (files, processes, threads, registry keys, etc.) is protected by a **DACL**:

- The DACL specifies **who has what access** to the object
- When code attempts to access an object, Windows performs an access check:
  - Does the caller's access token match the object's DACL?
  - Does the caller have the required access level?
- Access is **granted only if the checks pass**; otherwise, access is denied with an error

### Privileges: Special Rights

A **privilege** grants a security principal (user or process) the right to perform system-level operations:

**Common Privileges:**
- `SeTimeZonePrivilege` – Change system time zone
- `SeShutdownPrivilege` – Shut down the computer
- `SeLoadDriverPrivilege` – Load a device driver
- `SeBackupPrivilege` – Bypass file access restrictions for backup
- `SeRestorePrivilege` – Bypass file access restrictions for restore

**Powerful Privileges (Can Compromise the System):**

- **`SeDebugPrivilege`** – Obtain unrestricted read/write access to any process. This is one of the most dangerous privileges—with it, an attacker can inject code into SYSTEM processes or extract sensitive data from any process.
- **`SeTakeOwnershipPrivilege`** – Take ownership of any securable object (file, registry key, process). Allows bypassing permissions.
- **`SeRestorePrivilege`** – Replace any file on the system. Can be used to overwrite critical system binaries or plant malware.
- **`SeLoadDriverPrivilege`** – Load arbitrary device drivers into the kernel. Drivers run with kernel privileges and can compromise the entire system.
- **`SeCreateTokenPrivilege`** – Create arbitrary access tokens with any user, privilege, or domain group. Effectively grants unlimited privilege escalation.

**Privilege Management:**

- Privileges are **granted by system administrators** via Group Policy Objects (GPOs) or Local Security Policy (secpol)
- A privilege **must be enabled** before use using `AdjustTokenPrivileges` API
- Verify if a privilege is held using `LsaEnumerateAccountRights` or `CheckTokenMembership`

---

## Process Lifecycle Management

### Graceful Process Termination

When a process terminates cleanly:

- **`ExitProcess`** – Called by the process itself (usually when the primary thread's main function returns)
- All loaded DLLs (Dynamic Link Libraries) receive notification via their `DllMain` function with `DLL_PROCESS_DETACH`
- DLLs have an opportunity to perform cleanup (close file handles, release resources, save state)
- All threads are terminated orderly
- Resources are disposed of properly

### Ungraceful Process Termination

When a process is forcibly terminated:

- **`TerminateProcess`** – Called by another process to forcibly kill a target process
- All threads are terminated **immediately and abruptly**
- Loaded DLLs are **NOT** given an opportunity to clean up
- **Risk**: Data may be left in an inconsistent state, files may be left open, memory may leak, databases may be corrupted

**Key Difference:**
```
ExitProcess:      Self-termination → Graceful cleanup → Safe
TerminateProcess: Forced termination → No cleanup → Risk of data corruption
```

---

## Memory Architecture in Depth

### PE (Portable Executable) Layout in Memory

```
[PE Headers]
  ├─ DOS Header (0x40 bytes)
  ├─ PE Signature
  ├─ COFF Header
  └─ Optional Header (contains entry point)

[.text] (Code section)
  └─ Executable instructions

[.data] (Data section)
  └─ Global initialized variables

[.rdata] (Read-only data)
  └─ Constants, import table

[Relocation Table]
  └─ Addresses to patch during loading
```

### ASLR (Address Space Layout Randomization)

Modern Windows enables ASLR by default:
- Each process run has different base addresses
- **Impact on injection:** Can't hardcode addresses
- **Solution:** Use RIP-relative addressing (x64) or relocations
- **Bypass:** Leak addresses through info disclosure

### Import Address Table (IAT)

All imports from DLLs are resolved at load time:

```
User32.dll imports:
  MessageBoxA → 0x77d5e480
  CreateWindowA → 0x77d5f100
  ...
```

**Why it matters:**
- Inject code that needs Windows APIs? Must resolve or set up IAT
- Can hook IAT entries for API interception
- Position-independent code must use GetProcAddress() at runtime

---

## Critical Windows APIs

### Process Enumeration and Opening

```c
// Open existing process
HANDLE hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,  // Desired access
    FALSE,               // Inherit handle
    dwProcessId          // Target PID
);

// Create process
CreateProcessA(...)
```

**Access flags:**
- `PROCESS_VM_OPERATION` – Allocate/free memory
- `PROCESS_VM_READ` – Read process memory
- `PROCESS_VM_WRITE` – Write process memory
- `PROCESS_CREATE_THREAD` – Create threads
- `PROCESS_QUERY_INFORMATION` – Get process info
- `PROCESS_ALL_ACCESS` – All permissions (requires admin)

### Memory Operations

```c
// Allocate memory in target process
LPVOID lpBuffer = VirtualAllocEx(
    hProcess,           // Target process handle
    NULL,               // Preferred address (NULL for any)
    1024,               // Size
    MEM_COMMIT,         // Allocation type
    PAGE_EXECUTE_READWRITE  // Protection
);

// Write data to target process
BOOL success = WriteProcessMemory(
    hProcess,           // Target process
    lpBuffer,           // Remote address
    shellcode,          // Local buffer
    sizeof(shellcode),  // Size
    NULL                // Bytes written
);

// Read data from target process
BOOL success = ReadProcessMemory(
    hProcess,
    remoteAddress,
    localBuffer,
    size,
    NULL
);

// Free allocated memory
VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
```

**Memory protection flags:**
- `PAGE_EXECUTE` – Execute only
- `PAGE_EXECUTE_READ` – Execute + read
- `PAGE_EXECUTE_READWRITE` – Execute + read + write
- `PAGE_READWRITE` – Read + write only

### Thread Creation and Control

```c
// Create remote thread (execute code in target process)
HANDLE hThread = CreateRemoteThread(
    hProcess,           // Target process
    NULL,               // Thread attributes
    0,                  // Stack size (0 = default 1MB)
    (LPTHREAD_START_ROUTINE)lpBuffer,  // Entry point
    NULL,               // Thread parameter
    0,                  // Flags (0 = auto-start)
    NULL                // Thread ID
);

// Wait for thread to complete
WaitForSingleObject(hThread, INFINITE);

// Get thread exit code
DWORD dwExitCode;
GetExitCodeThread(hThread, &dwExitCode);

// Close handles
CloseHandle(hThread);
CloseHandle(hProcess);
```

### DLL Injection Specific APIs

```c
// Get address of exported function
HMODULE hModule = GetModuleHandle("kernel32.dll");
FARPROC pLoadLibrary = GetProcAddress(hModule, "LoadLibraryA");
```

---

## Injection Techniques - Deep Dive

### 1. Classic DLL Injection

**Overview:**
1. Allocate memory in target process
2. Write DLL path to allocated memory
3. Get address of `LoadLibraryA` in kernel32.dll
4. Create remote thread pointing to `LoadLibraryA`
5. Pass allocated memory (DLL path) as thread parameter

**Advantages:**
- Simple to implement
- Works reliably across Windows versions
- DLL handles all initialization

**Disadvantages:**
- Leaves traces (DLL loaded in target process)
- Requires DLL file on disk
- EDR/AV may block

**Code flow:**
```
Injector Process          Target Process
    │                           │
    ├─ AllocateMemory ─────────>│
    │                      [Memory allocated]
    │
    ├─ WriteDLL Path ──────────>│ (remote addr)
    │                      [DLL path written]
    │
    ├─ CreateRemoteThread ─────>│
    │     with LoadLibraryA     [Thread created]
    │                           │
    │                      [LoadLibraryA executes]
    │                      [DLL loads]
    │                      [DllMain() called]
    │                      [Code executes]
```

### 2. Shellcode Injection (Position-Independent Code)

**Overview:**
1. Allocate executable memory in target process
2. Write raw shellcode (position-independent)
3. Create remote thread pointing to shellcode
4. Shellcode executes without DLL dependencies

**Advantages:**
- No DLL file needed
- Smaller footprint
- More difficult to trace

**Disadvantages:**
- Must write position-independent code
- No automatic initialization
- Harder to handle complex functionality

**Position-Independent Code (PIC) Requirements:**
```asm
; x64 PIC requirements:
; - Use RIP-relative addressing for data
; - Don't hardcode addresses
; - Resolve APIs at runtime using GetProcAddress

; Example: Call MessageBoxA from shellcode
; 1. Find kernel32.dll base in PEB
; 2. Walk export table to find GetProcAddress
; 3. Call GetProcAddress("user32.dll")
; 4. Call GetProcAddress("MessageBoxA")
; 5. Call the resolved MessageBoxA function
```

### 3. Process Hollowing (RunPE)

**Overview:**
1. Create target process in suspended state (`CREATE_SUSPENDED`)
2. Unmap original PE image from process memory
3. Allocate new memory at preferred PE base
4. Write new PE image to target process
5. Update entry point and thread context
6. Resume process execution

**Advantages:**
- Process appears legitimate (uses real executable)
- Can hide parent-child process relationship
- Difficult to detect without instrumentation

**Disadvantages:**
- Complex to implement correctly
- Requires PE file understanding
- Can destabilize process

**Code flow:**
```
1. CreateProcessW(..., CREATE_SUSPENDED, ...)
2. GetThreadContext(hThread, &ctx)
   └─ Save original entry point
3. NtUnmapViewOfSection(hProcess, imageBase)
   └─ Remove original PE
4. VirtualAllocEx(hProcess, preferredBase, imageSize)
   └─ Allocate space for new PE
5. WriteProcessMemory(..., ntHeaders, ...)
   └─ Write new PE headers and sections
6. SetThreadContext(hThread, &newCtx)
   └─ Point to new entry point
7. ResumeThread(hThread)
   └─ Execute new code
```

### 4. APC Injection (Asynchronous Procedure Call)

**Overview:**
1. Allocate shellcode memory in target process
2. Write shellcode
3. Queue APC to target thread
4. When target thread enters alertable state (WaitForSingleObject, Sleep, etc.), APC executes
5. Shellcode runs in thread context

**Advantages:**
- No visible thread creation
- Harder to detect
- Executes in existing thread

**Disadvantages:**
- Thread must enter alertable state
- Limited to one thread
- May not execute immediately

**APC Functions:**
```c
// Queue APC to thread
DWORD QueueUserAPC(
    PAPC_FUNC pfnAPC,   // APC function pointer
    HANDLE hThread,     // Target thread
    ULONG_PTR dwData    // Parameter
);
```

### 5. Hook-based Injection

**Overview:**
1. Inject code that installs API hook
2. When target application calls hooked API, injected code executes
3. Can be chained to inject into multiple processes

**Example: SetWindowsHookEx**
```c
HHOOK hHook = SetWindowsHookEx(
    WH_GETMESSAGE,          // Hook type
    (HOOKPROC)HookFunction, // Hook callback
    hModule,                // DLL instance
    0                       // Thread (0 = all threads)
);
```

**Advantages:**
- Passive injection (no active hooking needed)
- Can target multiple processes
- Executes in response to system events

**Disadvantages:**
- Requires registering hook (may be monitored)
- Limited to specific APIs
- Removed when application unregisters

---

## Security Considerations

### Detection by EDR/AV

**Signature-based Detection:**
- Known injection patterns
- Suspicious API sequences
- Unusual memory allocations

**Behavior-based Detection:**
- Unexpected remote thread creation
- Memory allocation + write + execute
- Cross-process memory operations
- Unusual registry/file access from injected code

**Heuristic Detection:**
- Calls to kernel32 functions from unusual addresses
- Stack anomalies
- Suspicious entropy patterns

### Privilege Escalation

**SeDebugPrivilege:**
- Allows opening any process with PROCESS_ALL_ACCESS
- Required for most injection techniques
- Admin privs typically needed

### Access Token and Security Context

**Token inherited by injected thread:**
```
Injector Process Token
    ├─ User SID (e.g., Domain\User)
    ├─ Groups (Domain\Admins, etc.)
    ├─ Privileges (SeDebugPrivilege, etc.)
    └─ Integrity Level (High, Medium, Low)

Target Process Token
    └─ Injected code inherits target's token!
```

**Implication:**
- If target runs as SYSTEM, injected code runs as SYSTEM
- If target is sandboxed, injected code inherits sandbox

---

## Debugging Process Injection

### Using WinDbg

```
# Attach to target process
windbg -p <PID>

# Set breakpoint at VirtualAllocEx
bp kernel32!VirtualAllocEx

# View memory
db <address> L<count>   ; display bytes
dq <address>            ; display qwords

# Step through injector
p  ; step over
t  ; trace into

# View registers (x64)
rax, rcx, rdx, r8, r9, rip, rsp
```

### Using x64dbg

1. Attach to target process
2. Set breakpoint on `CreateRemoteThread`
3. Step and observe:
   - Memory allocations
   - Data written
   - Thread creation
   - Execution flow

### Detecting Active Injection

```powershell
# PowerShell: Monitor process creation and thread creation
Get-Process | Where {$_.ProcessName -eq "target"}
Get-Process | Get-Member

# Monitor with Process Monitor
# Filter: Process Name contains "notepad"
# Monitor: CreateRemoteThread, VirtualAllocEx, etc.
```

---

## Common Pitfalls

### 1. **Wrong Calling Convention**

**Problem:**
```c
// Wrong: mixing calling conventions
typedef int (__stdcall *pFunc)(int a, int b);
FARPROC pFn = GetProcAddress(...);
// pFn might be __cdecl, not __stdcall!
```

**Solution:**
```c
// Right: explicitly cast or verify
typedef int (WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
pMessageBoxA pMB = (pMessageBoxA)GetProcAddress(hUser32, "MessageBoxA");
```

### 2. **Not Closing Handles**

**Problem:**
```c
HANDLE hProcess = OpenProcess(...);
// ... forgot to close
// Result: Handle leak, resource exhaustion
```

**Solution:**
```c
HANDLE hProcess = OpenProcess(...);
// ... use it ...
CloseHandle(hProcess);  // Always close!
```

### 3. **Hardcoding Addresses (ASLR)**

**Problem:**
```c
// Wrong: assumes fixed address
LPVOID addr = (LPVOID)0x77d50000;  // kernel32 base
CreateRemoteThread(hProcess, NULL, 0, 
    (LPTHREAD_START_ROUTINE)addr, ...);
// Fails with ASLR enabled!
```

**Solution:**
```c
// Right: get address dynamically
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
FARPROC pFunc = GetProcAddress(hKernel32, "FunctionName");
```

### 4. **Insufficient Permissions**

**Problem:**
```c
// Fails: missing PROCESS_VM_OPERATION
HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
VirtualAllocEx(hProcess, ...);  // Fails!
```

**Solution:**
```c
// Right: request all needed access flags
HANDLE hProcess = OpenProcess(
    PROCESS_VM_OPERATION | PROCESS_VM_READ | 
    PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
    FALSE, pid
);
```

### 5. **Not Flushing Instruction Cache**

**Problem:**
```c
// CPU cache may have old instructions
WriteProcessMemory(hProcess, lpBuffer, shellcode, size, NULL);
CreateRemoteThread(hProcess, NULL, 0, 
    (LPTHREAD_START_ROUTINE)lpBuffer, ...);
// May execute cached old code!
```

**Solution:**
```c
WriteProcessMemory(hProcess, lpBuffer, shellcode, size, NULL);
FlushInstructionCache(hProcess, lpBuffer, size);
CreateRemoteThread(hProcess, NULL, 0, ...);
```

### 6. **Position-Dependent Code**

**Problem:**
```c
// Shellcode with hardcoded addresses
void shellcode() {
    void (*pFunc)() = (void (*)())0xdeadbeef;  // Wrong!
    pFunc();
}
```

**Solution:**
```asm
; x64 PIC: use RIP-relative addressing
lea rax, [rel data]     ; RIP-relative
mov rcx, [rax]          ; Read from data
```

---

## Performance and Optimization

### Memory Allocation Efficiency

```c
// Single large allocation
LPVOID lpBuffer = VirtualAllocEx(hProcess, NULL, 
    10000,  // Allocate 10KB at once
    MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// Better than multiple small allocations:
// VirtualAllocEx x 100 = 100 kernel transitions!
```

### Minimizing Shellcode Size

**Techniques:**
1. Remove unnecessary code
2. Use compression (Donut with `-z 2`)
3. Optimize for size (`-Os` in gcc)
4. Strip debug symbols

**Example:**
```bash
# Compile with size optimization
gcc -Os -s -o payload.exe payload.c -luser32

# Generate compressed shellcode
donut.exe -i payload.exe -o payload.bin -z 2
```

### Thread Synchronization

```c
// Wait for injected thread to complete
HANDLE hThread = CreateRemoteThread(...);
WaitForSingleObject(hThread, INFINITE);

// Alternative: Don't wait (thread runs independently)
CreateRemoteThread(...);
// Continue immediately
```

---

## Additional Resources

- **Windows API Reference**: https://learn.microsoft.com/en-us/windows/win32/
- **Windows Internals Book**: Pavel Yosifovich
- **Ghidra**: https://ghidra-sre.org/
- **x64dbg**: https://x64dbg.com/
- **Process Monitor**: https://docs.microsoft.com/en-us/sysinternals/downloads/procmon

---

## Disclaimer

This technical documentation is for educational and authorized security research only. Unauthorized process injection is illegal. Always obtain written authorization before conducting security testing.
