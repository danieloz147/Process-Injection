# AppDomainManager Injection

## Overview

This folder demonstrates .NET AppDomainManager-based injection: loading a custom `AppDomainManager` into a target process causes your code to execute as early as the CLR initializes. The sample `DomainManager` shows a message box on domain initialization.

This technique is powerful because the `AppDomainManager` is created by the runtime before most managed code executes.

> Ethical use only: Perform on systems you own or explicitly have permission to test. Misuse may be illegal.

---

## How It Works

- A class derives from `System.AppDomainManager` and overrides `InitializeNewDomain(AppDomainSetup)`.
- The CLR host is instructed to use your manager via configuration or environment variables.
- When the CLR initializes, it loads your assembly and instantiates your manager, running your code.

Sample manager in `ADM-Injection`:
- Namespace: `ADM_Injection`
- Type: `ADM_Injection.DomainManager`
- Target framework: .NET Framework 4.8 (`net48`)
- Shows a `MessageBox` in `InitializeNewDomain`.

---

## Build

Prerequisites:
- .NET Framework 4.8 Developer Pack (to build `net48`).
- Windows with Visual Studio or .NET SDK capable of building `net48` projects.

Commands (PowerShell):
```powershell
# Build the AppDomainManager DLL (default Debug, x64 output folder)
cd AppDomainManager-Injection/ADM-Injection

dotnet build

# Output: bin\x64\Debug\net48\ADM_Injection.dll
```

Bitness (architecture) matters:
- Match the target process architecture.
- If your host is 32-bit, build the DLL as x86; if 64-bit, build as x64.

To force x86 build:
```powershell
# Option A: one-off build switch
dotnet build -p:PlatformTarget=x86 -p:Prefer32Bit=true

# Output: bin\x86\Debug\net48\ADM_Injection.dll
```

To force x64 build:
```powershell
dotnet build -p:PlatformTarget=x64
```

---

## Configure the Host

You must tell the CLR to use your manager and make sure the assembly is loadable.

Option 1 — Place DLL next to the executable:
- Copy `ADM_Injection.dll` to the same directory as the target EXE (e.g., `ngentask.exe`).
- This is the simplest way to satisfy probing.

Option 2 — Add probing path via app.config:
Create `ngentask.exe.config` beside the EXE:
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <!-- Adjust relative path to your built DLL location -->
      <probing privatePath="AppDomainManager-Injection/ADM-Injection/bin/x64/Debug/net48" />
    </assemblyBinding>
    <!-- Optionally set the manager via config (some hosts honor this) -->
    <!-- <appDomainManagerType value="ADM_Injection.DomainManager" /> -->
  </runtime>
</configuration>
```

Option 3 — Specify the AppDomainManager in an application config file:
Create a `.config` file alongside the target executable, with a filename that matches the application (for example, `ngentask.exe.config`). Declare the assembly and type so the CLR uses your manager:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <runtime>
    <appDomainManagerAssembly value="ADM_Injection, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="ADM_Injection.DomainManager" />
  </runtime>
</configuration>
```

Ensure `ADM_Injection.dll` is loadable (ideally placed next to the EXE or resolvable via probing/GAC). The CLR will load the specified assembly and instantiate the given type as the `AppDomainManager`.

Option 4 — Environment variables (CLR `COMPLUS_`):
Some hosts honor environment variables for the manager assembly and type.
```powershell
# Set for current PowerShell session
$env:COMPLUS_AppDomainManagerAssembly = "ADM_Injection, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
$env:COMPLUS_AppDomainManagerType     = "ADM_Injection.DomainManager"
```
Notes:
- Ensure the assembly name matches the built DLL (`ADM_Injection.dll`).
- If you strong-name and GAC the assembly, use the real PublicKeyToken.

---

## Run with `ngentask.exe`

Assuming the host EXE is `ngentask.exe` (not provided in this repo), place the DLL next to it or set a probing path and environment variables, then run:
```powershell
# From the folder containing ngentask.exe
.\ngentask.exe
```
You should see a "Success" message box.

## Expected Behavior

- **AppDomainManager (net48)**: On CLR initialization, the runtime loads `ADM_Injection.dll` and instantiates `ADM_Injection.DomainManager`. During `InitializeNewDomain(AppDomainSetup)`, a WinForms dialog appears with title "Success" and message "Hello World". This occurs before the application's managed entry point (`Main`).
- **Startup Hooks (.NET Core 3+ / .NET 5+)**: With `DOTNET_STARTUP_HOOKS` set, the runtime calls `StartupHook.Initialize()` synchronously on the same thread that will execute `Main`. Expect any hook output (console/UI) to appear first; non-blocking work should continue in background threads while the host app proceeds.

---

## Troubleshooting

- FileNotFoundException: The system cannot find the file specified
  - Cause: The CLR cannot locate `ADM_Injection.dll`.
  - Fix: Copy the DLL beside the EXE, or set a probing path in `ngentask.exe.config`.

- BadImageFormatException: An attempt was made to load a program with an incorrect format
  - Cause: Architecture mismatch (x86 vs x64).
  - Fix: Build the DLL for the same bitness as the host process.
    - Verify host bitness: Use Task Manager (32-bit processes show *(*32 bit)*) or tools like Sysinternals `sigcheck`.
    - Rebuild with `-p:PlatformTarget=x86` or `-p:PlatformTarget=x64` accordingly.

- AppDomainManager not created
  - Cause: Host ignores config/env, or type name mismatch.
  - Fix: Check `COMPLUS_AppDomainManagerAssembly` and `COMPLUS_AppDomainManagerType` values; confirm namespace and type.

- WinForms type not found
  - Cause: Missing WinForms on non-Windows or wrong target framework.
  - Fix: Ensure `net48` and `<UseWindowsForms>true</UseWindowsForms>` in the project; run on Windows.

---

## .NET Startup Hooks (Alternative)

For .NET 5+/.NET 6+, Startup Hooks can run code early without a custom AppDomainManager. See `StartUp-Hooks` for a sample. High level steps:
- Build the startup hook assembly.
- Set `DOTNET_STARTUP_HOOKS` to the assembly path before launching the host.

Example:
```powershell
$env:DOTNET_STARTUP_HOOKS = "C:\path\to\StartupHook.dll"
.\SomeNet6Host.exe
```

### Technical Details
- **Runtime support**: Introduced in .NET Core 3; available on .NET 5/6/7/8 across Windows, Linux, macOS. Not available on .NET Framework.
- **Hook shape**: A managed DLL defining a class named `StartupHook` with a static method `Initialize()`; best practice is no namespace. Signature: `public static void Initialize()`.
- **Execution timing**: Runs synchronously on the same thread that will call `Main`; keep work minimal and non-blocking. Spawning worker threads inside `Initialize()` is acceptable.
- **Activation**: Provide one or more absolute DLL paths via `DOTNET_STARTUP_HOOKS`. Multiple hooks are separated by `;` and execute left-to-right.
- **Resolution**: Hook assemblies are loaded by the runtime; ensure dependencies are resolvable (same folder or probing paths). Hooks execute before the app entry point.
- **Cross-platform**: Works for self-contained or framework-dependent apps; paths and DLL formats must match host OS.
- **Use cases**: Observability (logging/telemetry), policy enforcement, instrumentation. Handle with care due to security implications.

Reference and further reading: .NET Startup Hooks by Rasta Mouse — https://rastamouse.me/net-startup-hooks/

---

## Repo Paths

- Manager implementation: `AppDomainManager-Injection/ADM-Injection/AppDomainManager-Injection-dll.cs`
- Project file: `AppDomainManager-Injection/ADM-Injection/ADM-Injection.csproj`
- Built output (default): `AppDomainManager-Injection/ADM-Injection/bin/x64/Debug/net48/ADM_Injection.dll`
- Alternative technique: `AppDomainManager-Injection/StartUp-Hooks`

---

## Security Considerations

- Use strictly for authorized testing and research.
- Do not deploy on production systems without consent and change control.
- Keep assemblies unsigned and private unless you understand strong-naming/GAC implications.

## References

- Microsoft Docs: AppDomainManager class
- .NET runtime configuration: Probing paths and assembly binding
- .NET Startup Hooks (dotnet/runtime docs)
- Rasta Mouse: .NET Startup Hooks — https://rastamouse.me/net-startup-hooks/
