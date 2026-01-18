# SimpleMessageBox — Build Guide and Educational Notes

This folder contains a tiny Windows program that shows a classic message box. It’s a minimal, benign example used to demonstrate compiling a Windows PE and to provide high‑level (non‑actionable) educational context about “shellcode” and tooling discussed in security research.

Important: Do not use any information here to violate laws or policies. Only perform security testing on systems you own or are explicitly authorized to test.

## What It Does

The program in [Shellcode/SimpleMessageBox.c](SimpleMessageBox.c) simply calls `MessageBoxA`:

```c
#include <windows.h>

int main() {
		MessageBoxA(NULL, "It's working!", "Simple Message Box", MB_OK);
		return 0;
}
```

## Prerequisites

- Windows 10/11
- One of the following build toolchains:
	- Microsoft Visual C++ (MSVC) — e.g., Visual Studio or Build Tools
	- MinGW-w64 (for `gcc`)

## Build

You can build with either MSVC or MinGW. Pick one approach below.

### Build with MinGW (gcc)

```bash
gcc -o SimpleMessageBox.exe SimpleMessageBox.c
```

This produces `SimpleMessageBox.exe` in the current directory.

## Run

```powershell
./SimpleMessageBox.exe
```

You should see a message box titled "Simple Message Box" with the text "It's working!".

## Educational Note: “Shellcode” (High-Level Only)

In security research, “shellcode” often refers to position‑independent machine code intended to be injected into a process and executed. While benign examples sometimes use a trivial message box as a proof of concept, writing, extracting, and running shellcode are sensitive topics with serious legal and ethical implications.

This project focuses on a harmless PE executable that shows a message box. It does not include or endorse instructions for generating or executing shellcode, nor for process injection.

## Generation: Language, Size, and Design Choices

### Why C Instead of Pure Assembly?

This example uses **C** (compiled to native machine code) rather than hand-written assembly for several practical reasons:

- **Portability**: C code compiles to different architectures (x86, x64) without rewriting.
- **Maintainability**: C is more readable and easier to modify than raw assembly.
- **Simplicity**: For a proof-of-concept, C abstracts away low-level details.
- **Compiler Optimization**: Modern compilers (gcc, MSVC) produce compact, efficient machine code.

### Traditional Shellcode vs. Donut Approach

**Traditional Shellcode (Pure Assembly)**
- Hand-written assembly code (~50–500 bytes for simple tasks)
- Position-independent by design
- Requires deep knowledge of x86/x64 instruction set and Windows APIs
- Common in exploit development for minimal footprint

**Donut Approach (C → PE → Position-Independent Shellcode)**
- Write code in a higher-level language (C, C#, .NET)
- Compile to a PE executable
- Donut wraps the PE in a loader and converts it to position-independent code
- Larger footprint but much easier to develop and maintain
- Supports complex functionality without manual assembly

### Typical Shellcode Sizes

For `SimpleMessageBox.exe`:

- **Compiled `.exe`**: ~7–15 KB (includes full PE headers, imports, runtime)
- **Raw shellcode (via Donut)**: ~30–60 KB (depends on compression and encryption settings)
  - With `-z 2` (aPLib compression): Typically reduces size by 40–60%
  - With `-e 3` (full entropy/encryption): Adds obfuscation overhead

**Why the increase?**
- Donut embeds the entire PE binary and a position-independent loader
- Encryption and compression layers add metadata
- The loader handles runtime environment setup

### Size Optimization Tips

- Use `-z 2` (aPLib compression) to reduce shellcode size
- Use minimal C code (avoid unnecessary dependencies)
- Compile with `-Os` (optimize for size) instead of `-O2`
- Remove debug symbols: compile without `-g` flag

### Example with Size Optimization

```bash
# Compile for minimal size
gcc -Os -s -o SimpleMessageBox.exe SimpleMessageBox.c

# Generate smallest possible shellcode
donut.exe -i SimpleMessageBox.exe -o SimpleMessageBox.bin -z 2 -k 2 -e 1 -b 1
```

The `-e 1` (no encryption) reduces overhead but is less stealthy. Use `-e 3` for maximum obfuscation in authorized testing.

## Extracting Shellcode with Donut

[Donut](https://github.com/TheWover/donut) is a shellcode generation tool that can convert .NET assemblies and native PE files into position-independent shellcode.

**Important**: Only use this on systems you own or have explicit authorization to test. This is for educational and authorized security research only.

### Prerequisites

- Download Donut from https://github.com/TheWover/donut/releases
- Built `SimpleMessageBox.exe` (see Build section above)

### Generate Shellcode

To convert `SimpleMessageBox.exe` to shellcode and output to a `.bin` file:

```powershell
donut.exe -i SimpleMessageBox.exe -o SimpleMessageBox.bin -z 2 -k 2 -e 3 -b 1
```

This creates `SimpleMessageBox.bin` containing the position-independent shellcode.

### Common Donut Options

- `-i <file>` - Input PE file or .NET assembly to convert
- `-o <file>` - Output file for shellcode (default: loader.bin)
- `-a <arch>` - Target architecture: 1=x86, 2=x64, 3=x86+x64 (default: 3)
- `-z <compress>` - Compression: 1=none, 2=aPLib, 3=LZNT1, 4=Xpress (default: 1)
- `-k <bypass>` - Bypass AMSI/WLDP: 1=none, 2=abort on fail, 3=continue on fail (default: 3)
- `-e <entropy>` - Entropy level: 1=none, 2=random names, 3=random + symmetric encryption (default: 3)
- `-b <behavior>` - Loader behavior: 1=exit thread, 2=exit process, 3=do not exit (default: 1)
- `-p <params>` - Parameters to pass to the PE's entry point

### Example with Options

```powershell
# Generate x64-only shellcode with full encryption and compression
donut.exe -i SimpleMessageBox.exe -o SimpleMessageBox.bin -a 2 -z 2 -k 2 -e 3 -b 1
```

### Verify the Output

You can check the generated shellcode file:

```powershell
Get-Item SimpleMessageBox.bin | Select-Object Name, Length
```

The `.bin` file contains raw shellcode bytes that can be used in authorized process injection testing.

### Extract Shellcode as Hexadecimal

To convert the `.bin` file to hexadecimal format (useful for embedding in code or analysis):

**PowerShell:**

```powershell
$bytes = [System.IO.File]::ReadAllBytes('shell.bin')
$hex = -join ($bytes | ForEach-Object { $_.ToString('X2') })
Write-Output $hex | Out-File shellcode.hex

# Or formatted with commas (for C/C++ arrays):
$hex = -join ($bytes | ForEach-Object { '0x' + $_.ToString('X2') + ',' })
Write-Output $hex | Out-File shellcode_formatted.hex
```

**Python:**

```python
with open('SimpleMessageBox.bin', 'rb') as f:
    data = f.read()
    hex_str = data.hex()
    print(hex_str)
    
# Or with 0x prefix and commas:
with open('SimpleMessageBox.bin', 'rb') as f:
    data = f.read()
    hex_formatted = ', '.join([f'0x{byte:02x}' for byte in data])
    with open('shellcode_formatted.hex', 'w') as out:
        out.write(hex_formatted)
```

**Command Line (Windows):**

```powershell
certutil -encodehex SimpleMessageBox.bin shellcode.hex 2
```

### Example Output Format

The hex output will look like:

```
4d5a900003000000... (continues for entire file)
```

Or with formatting for C/C++ embedding:

```c
unsigned char shellcode[] = {
    0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, ...
};
```

## EDR/AV Evasion — Not Covered in This Repository

### What Is EDR/AV Evasion?

In the security community, "EDR/AV evasion" refers to techniques designed to avoid detection by Endpoint Detection and Response (EDR) systems and antivirus (AV) software. This includes:

- Obfuscating shellcode (e.g., encryption, polymorphism)
- Avoiding known malicious signatures
- Bypassing behavior-based detection heuristics
- Evading memory scanning and API hooking
- Circumventing AMSI (Antimalware Scan Interface) and WLDP (Windows Defender Application Guard)

### What This Repository Does **NOT** Teach

**This repository explicitly does not provide:**

- Step-by-step evasion techniques or bypasses
- Methods to hide shellcode from security tools
- Tactics to disguise malicious activity as legitimate
- Configuration guides for evading specific EDR/AV products
- Code obfuscation or polymorphic shellcode generation (beyond Donut's built-in options)

### Our Approach

The tools and examples here (gcc, Donut) have some defensive capabilities (e.g., Donut's `-k` and `-e` flags), but:

- These are **not** presented as evasion techniques
- We acknowledge their existence for transparency in authorized testing
- We **strongly discourage** using them to bypass security controls on systems you do not own or test without authorization

### Responsible Security Research

If you are conducting legitimate, authorized penetration testing or red team exercises:

- Always obtain written authorization from the system owner
- Work within a controlled, isolated environment
- Document all activities for audit and compliance
- Coordinate with your organization's security and legal teams
- Respect responsible disclosure practices

**Unauthorized evasion of security controls is illegal in most jurisdictions and violates computer fraud and abuse laws.**

## Disclaimer

This material is for educational and legitimate development purposes only. Do not attempt any activity that could harm systems, violate laws, or breach terms of service. You are solely responsible for how you use this information.


