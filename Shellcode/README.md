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

## Disclaimer

This material is for educational and legitimate development purposes only. Do not attempt any activity that could harm systems, violate laws, or breach terms of service. You are solely responsible for how you use this information.


