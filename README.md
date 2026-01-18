# Process-Injection

This repository provides educational material about process injection—a fundamental technique in systems programming and security research. It includes examples, explanations, and practical demonstrations intended for authorized security testing and learning only.

**Important Disclaimer**: Do not use this information to compromise systems you do not own or have explicit authorization to test. Unauthorized process injection is illegal in most jurisdictions and violates computer fraud and abuse laws.

⚠️ **Critical Information**: More detailed technical documentation, security considerations, and step-by-step implementation guides are located in:
- [TECHNICAL.md](TECHNICAL.md) – In-depth Windows internals, API details, and processes in general
- [Shellcode/README.md](Shellcode/README.md) – Shellcode generation and extraction
- [Classic-Injection/README.md](Classic-Injection/README.md) – Classic injection technique

These files contain essential information about prerequisites, compilation steps, and security implications.

## What Is Process Injection?

Process injection is a technique where code is inserted into a running process and executed within that process's memory space and security context. Instead of starting a new process, the injected code runs inside an existing process.

### High-Level Overview

```
Normal Execution:
Your Code → New Process Created → Code Runs in New Context

Process Injection:
Your Code → Injected into Running Process → Code Runs in Existing Context
```

### Why Process Injection Matters

**Legitimate Uses:**
- Debugging and instrumentation
- Performance monitoring and profiling
- Plugin systems and code extensions
- Authorized penetration testing and red team exercises

**Security Research Context:**
- Understanding how malware operates
- Testing EDR/security tool effectiveness (with authorization)
- Defensive security research and tool development

---

## Prerequisites: Knowledge Required Before Starting

Before attempting to understand or implement process injection, you should have solid foundations in:

### 1. **Windows Operating System Fundamentals**
- Process and thread concepts
- Memory management (virtual memory, heaps, stacks)
- Windows process API basics (`CreateProcess`, `OpenProcess`, etc.)
- Process handles and access tokens
- Understanding of process privilege levels (user, admin, SYSTEM)

**Resources:**
- Windows API documentation (Microsoft Docs)
- "Windows Internals" by Pavel Yosifovich
- Sysinternals tools (Process Monitor, Process Explorer)

### 2. **C/C++ Programming**
- Pointer manipulation and memory management
- Struct definitions and data type layouts
- Windows API function calls and error handling
- Casting and type conversions
- DLL basics and linking

**Key Concepts:**
- `void*` pointer arithmetic
- Structure packing and alignment
- Calling conventions (stdcall, cdecl)
- Return codes and error checking

### 3. **Machine Code and Assembly Language**
- Basic x86/x64 instruction set familiarity
- Stack frames and function calls
- Register usage (EAX, RCX, RSP, etc.)
- Basic shellcode concepts
- Position-independent code (PIC)

**Resources:**
- IDA Pro or Ghidra (disassembly tools)
- "Assembly Language Step-by-Step" by Jeff Duntemann

### 4. **Windows API and System Calls**
- **Critical APIs for injection:**
  - `VirtualAllocEx()` – Allocate memory in target process
  - `WriteProcessMemory()` – Write data to target process
  - `CreateRemoteThread()` – Execute code in target process
  - `OpenProcess()` – Obtain handle to target process
  - `GetProcAddress()` – Resolve function addresses
  - `LoadLibrary()` / `GetModuleHandle()` – DLL loading

- **Supporting APIs:**
  - `CloseHandle()`, `FlushInstructionCache()`, `WaitForSingleObject()`

### 5. **Understanding Process Memory Layout**
- Executable (.text) section
- Data sections (.data, .rdata)
- Import Address Table (IAT)
- Thread Local Storage (TLS)
- Heap vs. stack allocation
- ASLR (Address Space Layout Randomization) and implications

### 6. **Security Concepts**
- Access control and privilege escalation
- Windows security attributes
- Code signing and verification
- Antivirus/EDR detection methods (signature, behavior, heuristic)
- AMSI (Antimalware Scan Interface) and WLDP (Windows Defender Application Guard)

### 7. **Debugging and Analysis Tools**
- **Debuggers:** WinDbg, x64dbg, Visual Studio Debugger
- **Disassemblers:** IDA Pro, Ghidra
- **Process monitors:** Process Monitor, Process Explorer
- **Reverse engineering:** Understanding PE file format

---

## Types of Process Injection (High-Level Overview)

This repository covers several injection techniques:

### 1. **Classic DLL Injection**
- Inject a DLL path into a target process
- Target process calls `LoadLibrary()` to load the DLL
- DLL's `DllMain()` executes in target context
- Simplest approach but leaves traces

### 2. **Shellcode Injection**
- Inject raw machine code (shellcode) into target process memory
- Allocate memory, write code, execute via `CreateRemoteThread()`
- More direct and potentially stealthier
- Requires position-independent code

### 3. **Process Hollowing / Runpe**
- Create a new process in suspended state
- Unmap its original image from memory
- Inject new code into the clean memory space
- Resume the process (appears to run legitimate executable)

### 4. **APC Injection (Asynchronous Procedure Call)**
- Queue an APC to a target thread
- APC executes in target thread context when it enters alertable state
- More subtle than `CreateRemoteThread()`

### 5. **Hook-based Injection**
- Inject into processes that load specific DLLs
- Common targets: Notepad, Explorer, browser processes

---

## Repository Structure

- **[Shellcode/](Shellcode/)** – Building and extracting shellcode using Donut
- **[Classic-Injection/](Classic-Injection/)** – DLL injection examples
- **[Advanced Techniques/](Advanced-Techniques/)** *(placeholder)* – Process hollowing, APC injection, etc.

---

## Prerequisites Before Using This Repository

### System Requirements
- **Windows 10/11** (examples target modern Windows)
- **Administrator privileges** recommended (for testing certain techniques)
- **Isolated test environment** strongly recommended

### Development Tools
- **C/C++ Compiler:** MSVC (Visual Studio) or MinGW-w64
- **Debugger:** WinDbg, x64dbg, or Visual Studio Debugger
- **Disassembler:** IDA Pro or Ghidra (optional but recommended)

### Knowledge Checklist

Before diving into the code, ensure you understand:

- ✓ Windows process model and memory management
- ✓ C/C++ pointers, structs, and memory operations
- ✓ Basic x86/x64 assembly (at least recognize common instructions)
- ✓ Windows API documentation and error handling patterns
- ✓ PE file format basics
- ✓ Security implications of running arbitrary code

---

## Legal and Ethical Guidelines

**This repository is for educational purposes only.**

### You Must Have Written Authorization

- Only perform process injection on systems you own
- Never test on systems without explicit, documented permission
- Work in isolated lab environments
- Ensure your organization's security and legal teams approve any testing

### Unauthorized Access Is a Crime

- Computer Fraud and Abuse Act (CFAA) – United States
- Computer Misuse Act – United Kingdom
- Similar laws exist in most jurisdictions

### Responsible Disclosure

- If you discover a vulnerability, follow responsible disclosure practices
- Report issues to affected organizations through proper channels
- Allow adequate time for patches before public disclosure

---

## Getting Started

1. **Review prerequisites** – Ensure you have the foundational knowledge
2. **Study Windows API** – Familiarize yourself with process and memory APIs
3. **Start with examples** – Begin with the Shellcode section and Classic Injection
4. **Experiment safely** – Use isolated VMs or dedicated lab machines
5. **Document everything** – Keep notes on what you learn and test

---

## Additional Resources

- **Microsoft Docs:** Windows API Reference
- **Ghidra:** Free disassembly framework
- **x64dbg:** Open-source x86/x64 debugger
- **Windows Internals:** Official Microsoft documentation
- **OWASP and CWE:** Security vulnerability classification

---

## Disclaimer

This material is for educational and authorized security research only. You are solely responsible for how you use this information. Unauthorized access to computer systems is illegal. Always obtain written authorization before conducting any security testing.
