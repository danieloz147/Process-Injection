# Shellcode DLL

## Overview

This is a simple DLL designed for testing DLL sideloading and injection techniques. When loaded into a process, it displays a message box to confirm successful injection.

## Description

The DLL uses the `DllMain` entry point to execute code when it's loaded into a process. Upon attachment (`DLL_PROCESS_ATTACH`), it displays a message box with the text "DLL SideLoad Success".

### Key Features

- **Simple Indicator**: Shows a visible message box to confirm DLL loading
- **Process Attachment Hook**: Executes automatically when the DLL is loaded
- **Minimal Dependencies**: Only requires `windows.h` and `user32.dll`

## Compilation

To compile the DLL, use GCC with the following command:

```bash
gcc -shared -o shellcode-dll.dll shellcode-dll.c -luser32
```

### Requirements

- MinGW GCC compiler
- Windows environment
- `user32` library (for MessageBox API)

## Usage

### DLL Sideloading

1. Identify a vulnerable application that loads DLLs from its application directory
2. Rename the compiled DLL to match the expected DLL name
3. Place it in the application's directory
4. Execute the application
5. The message box should appear, confirming successful sideloading

### DLL Injection

This DLL can also be injected using various injection techniques:
- Classic DLL Injection (`LoadLibrary` + `CreateRemoteThread`)
- Reflective DLL Injection
- Manual Mapping
- Process Hollowing

## Security Considerations

⚠️ **Warning**: This tool is for educational and authorized security testing purposes only. Unauthorized use of DLL injection techniques may be illegal.

### Ethical Use

- Only use on systems you own or have explicit permission to test
- Understand the legal implications in your jurisdiction
- Use responsibly and ethically

## Related Techniques

This DLL can be used in conjunction with other process injection methods in this repository:
- [Classic Injection](../Classic-Injection/)
- [Classic Remote Injection](../Classic-Remote-Injection/)
- [Process Hollowing](../Process-Hollowing/)
- [Thread Hijacking](../Thread-Hijacking/)

## Output

When successfully loaded, the DLL displays:
- **Title**: "Hello"
- **Message**: "DLL SideLoad Success"
- **Type**: Information dialog with OK button
