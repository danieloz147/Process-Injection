#include <windows.h>

// Entry point for the DLL
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL, // handle to DLL module
    DWORD fdwReason,    // reason for calling function
    LPVOID lpvReserved  // reserved
) {
    // Perform actions based on the reason for calling
    if (fdwReason == DLL_PROCESS_ATTACH) { 
        // Show a message box when the DLL is loaded (sideloaded)
        // Shellcode execution point
        MessageBoxA(
            NULL,
            "DLL SideLoad Success",
            "Hello",
            MB_OK | MB_ICONINFORMATION
        );
    }
    return TRUE;
}
