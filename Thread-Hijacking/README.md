# Thread Hijacking

This folder demonstrates **thread hijacking** - a process injection technique where an existing thread is suspended, its execution context is modified, and then resumed to execute shellcode.

**Important Disclaimer**: This code is for educational purposes only on systems you own or have explicit authorization to test. Unauthorized injection is illegal.

---

## What Is Thread Hijacking?

Thread hijacking (also called context hijacking) involves:

1. **Create Thread (Suspended)** – Use `CreateThread()` with `CREATE_SUSPENDED` flag
2. **Allocate Memory** – Use `VirtualAlloc()` to allocate executable memory in current process
3. **Write Shellcode** – Use `WriteProcessMemory()` to copy shellcode to the allocated memory
4. **Get Context** – Use `GetThreadContext()` to read the thread's CPU registers
5. **Modify Context** – Change the RIP (Instruction Pointer) to point to shellcode
6. **Set Context** – Use `SetThreadContext()` to write the modified registers back
7. **Resume Thread** – Use `ResumeThread()` to execute from the new RIP (shellcode)

### In This Folder

The example demonstrates **self-process thread hijacking** - creating and hijacking a thread within the same process.

### Alternative Variant: Hijacking Existing Threads

An alternative approach involves enumerating existing threads in a running process, suspending a selected thread, modifying its context, and resuming execution. However, this method is **generally discouraged** because hijacking an active thread disrupts its original functionality and can destabilize or crash the target process.

**Flow:**
```
Main Process
    │
    ├─ VirtualAlloc() → Allocate memory for shellcode
    │
    ├─ WriteProcessMemory() → Write shellcode to memory
    │
    ├─ CreateThread(CREATE_SUSPENDED) → Create suspended thread
    │
    ├─ GetThreadContext() → Read thread's registers
    │
    ├─ Modify RIP → Point to shellcode address
    │
    ├─ SetThreadContext() → Write modified registers
    │
    └─ ResumeThread() → Execute shellcode
```

---

## Code Breakdown

### Allocating Memory

```c
LPVOID HandleMemory = VirtualAlloc(
    NULL,                       // Preferred address (NULL = let OS choose)
    sizeof(shellcode),          // Size to allocate
    MEM_COMMIT,                 // Allocate and commit pages
    PAGE_EXECUTE_READWRITE      // Make memory executable + readable + writable
);
```

Allocates executable memory in the current process to hold the shellcode.

### Writing Shellcode

```c
SIZE_T bytesWritten = 0;
BOOL RESULT = WriteProcessMemory(
    GetCurrentProcess(),    // Current process handle
    HandleMemory,           // Address in current process
    shellcode,              // Shellcode buffer
    sizeof(shellcode),      // Size to copy
    &bytesWritten           // Bytes written
);
```

Copies shellcode bytes into the allocated memory.

### Creating Suspended Thread

```c
DWORD threadId = 0;
HANDLE hThread = CreateThread(
    NULL,                       // Security attributes (NULL = default)
    0,                          // Stack size (0 = default 1MB)
    (LPTHREAD_START_ROUTINE)dummyFunction,  // Entry point (dummy function)
    NULL,                       // Thread parameter
    CREATE_SUSPENDED,           // Create in suspended state
    &threadId                   // Output: Thread ID
);
```

Creates a new thread but doesn't execute it yet (suspended state).

### Getting Thread Context

```c
CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_ALL;  // Read all register information

GetThreadContext(hThread, &ctx);
printf("Original RIP: 0x%p\n", (void*)ctx.Rip);
```

Reads the thread's CPU registers including RIP (Instruction Pointer).

### Modifying RIP to Point to Shellcode

```c
ctx.Rip = (DWORD64)HandleMemory;
printf("Modified RIP to point to shellcode at address: 0x%p\n", (void*)ctx.Rip);
```

Changes the RIP register to the shellcode address so execution starts there.

### Setting Modified Context

```c
SetThreadContext(hThread, &ctx);
```

Writes the modified context (with new RIP) back to the thread.

### Resuming Execution

```c
ResumeThread(hThread);
printf("Thread resumed to execute shellcode.\n");
```

Resumes the thread - it now executes from the shellcode address.

### Cleanup

```c
WaitForSingleObject(hThread, INFINITE);  // Wait for thread to complete
CloseHandle(hThread);                      // Close thread handle
VirtualFree(HandleMemory, 0, MEM_RELEASE); // Free allocated memory
```

Waits for the thread to finish, then releases resources.

---

## Prerequisites

### System Requirements
- Windows 10/11 (examples target modern Windows)
- Isolated test environment **strongly recommended**

### Development Tools
- **C/C++ Compiler:** MSVC (Visual Studio) or MinGW-w64
- **Debugger:** WinDbg, x64dbg, or Visual Studio Debugger (optional)

### Knowledge Requirements
- Understanding of Windows thread API (CreateThread, GetThreadContext, SetThreadContext)
- Understanding of CPU registers (RIP, RSP, etc.)
- Understanding of shellcode (position-independent machine code)
- Context structure and ContextFlags

---

## How It Works: Step-by-Step

```
┌──────────────────────────────────────────────────────┐
│ Main Process Starts                                  │
└─────────────┬───────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────┐
│ VirtualAlloc()                                       │
│ ├─ Allocate executable memory                        │
│ └─ Return address: 0x0000000002A40000               │
└─────────────┬───────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────┐
│ WriteProcessMemory()                                 │
│ ├─ Copy shellcode to allocated memory                │
│ └─ Memory now executable with shellcode              │
└─────────────┬───────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────┐
│ CreateThread(CREATE_SUSPENDED)                       │
│ ├─ Create new thread pointing to dummyFunction       │
│ ├─ Thread paused (not executing)                     │
│ └─ RIP currently points to dummyFunction entry       │
└─────────────┬───────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────┐
│ GetThreadContext()                                   │
│ ├─ Read all thread registers (RIP, RSP, RAX, etc.)   │
│ └─ ctx.Rip = 0x7FFF0000 (dummyFunction address)     │
└─────────────┬───────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────┐
│ Modify RIP                                           │
│ ├─ ctx.Rip = 0x0000000002A40000 (shellcode)         │
│ └─ Other registers unchanged                         │
└─────────────┬───────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────┐
│ SetThreadContext()                                   │
│ ├─ Write modified context back to thread             │
│ └─ Thread still suspended with new RIP               │
└─────────────┬───────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────┐
│ ResumeThread()                                       │
│ ├─ Resume suspended thread                           │
│ ├─ Thread wakes up and reads new RIP                 │
│ └─ Starts executing from shellcode address           │
└─────────────┬───────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────┐
│ Thread Executes Shellcode                            │
│ ├─ Runs payload (MessageBox, etc.)                   │
│ └─ Thread completes and exits                        │
└─────────────┬───────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────┐
│ Cleanup                                              │
│ ├─ WaitForSingleObject() → Wait for thread           │
│ ├─ CloseHandle(hThread)                              │
│ └─ VirtualFree() → Release memory                    │
└─────────────┬───────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────┐
│ Program Exit                                         │
└──────────────────────────────────────────────────────┘
```

---

## Advantages of Thread Hijacking

✓ **Self-process** – No need for remote process access
✓ **No privileges required** – Works in user-mode processes
✓ **Stealthy** – Reuses existing thread instead of creating new one
✓ **Flexible** – Can hijack any thread in current process
✓ **Low detection** – Less obvious than CreateThread artifacts

---

## Limitations and Risks

✗ **Limited to current process** – Can't hijack threads in other processes
✗ **Thread state dependent** – Thread must be accessible and not protected
✗ **Context switching** – Requires careful register manipulation
✗ **Architecture specific** – RIP vs EIP varies (64-bit vs 32-bit)
✗ **May break original execution** – If target was doing something important

---

## Legal and Ethical Considerations

**Authorization Required:**
- Only use on systems you own
- Never test on systems without explicit written permission
- Works in authorized penetration testing scenarios only

**Responsible Disclosure:**
- Report findings through proper channels
- Give organizations time to patch
- Follow your organization's security policies

**Legal Implications:**
- Unauthorized code injection is illegal (Computer Fraud and Abuse Act in US)
- Similar laws exist in other jurisdictions
- Violations can result in criminal charges

---

## References

- [CreateThread Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)
- [GetThreadContext Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)
- [SetThreadContext Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext)
- [ResumeThread Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
- [CONTEXT Structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context)
- [Windows Internals](https://learn.microsoft.com/en-us/sysinternals/)

---

## Disclaimer

This code and documentation are provided for educational purposes on authorized systems only. Unauthorized process injection is illegal and violates computer fraud laws. You are solely responsible for compliance with applicable laws and organizational policies.
