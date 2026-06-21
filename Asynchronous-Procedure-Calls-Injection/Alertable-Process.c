#include <windows.h>
#include <stdio.h>

int main() {
    printf("Target process PID: %lu\n", GetCurrentProcessId());
    printf("Process is now in alertable state (sleeping)...\n");
    
    // The process enters an alertable state
    SleepEx(INFINITE, TRUE);  // Sleep indefinitely in alertable state - the APC will execute here
    
    return 0;
}