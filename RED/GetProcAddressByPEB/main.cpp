#include "windows.h"
#include "stdio.h"

//typedef void(*func)();
VOID WINAPI Lower(WCHAR* s) {
	WCHAR* pos = s;
	for (; *pos; pos++) {
		if (*pos <= 'Z' && *pos >= 'A')
			*pos |= 0x20;
	}
	//printf("\t==lower string : %ws\n", s);
}

 BOOL WINAPI __strcmpW(WCHAR* a, WCHAR *b) {
	//printf("\tcompared dll name: %ws\n\n", b);

	int i = 0;
	for (i = 0; a[i] || b[i]; i++)
		if (a[i] != b[i])
			return FALSE;
	return TRUE;
}

HMODULE WINAPI FindModuleByPeb(WCHAR* targetModule) {
	WCHAR dllName[50] = { 0 };
	BOOL foundModule = FALSE;
	DWORD dllBase = NULL; 
	printf("[#] start get module handle\n");
	/*
		通过PEB结构中的Ldr寻找到InLoadOrderModuleList，遍历寻找已加载的模块，通过模块名进行寻找
	*/
	__asm {
		push targetModule
		call Lower
		mov eax, fs:[30h]		// eax <- peb
		mov eax, [eax + 0ch]		// eax <- Ldr  _PEB_LDR_DATA
		mov eax, [eax + 0ch]		// eax <- first Flink address, InLoadOrderModuleList [Type: _LIST_ENTRY]
	_LOOP :
		push eax
		mov eax, [eax + 2ch + 4]		// dll name string address
		cmp eax, 0
		jz _END				// 字符串为NULL，说明寻找完毕，退出
		lea ebx, dllName
		push ebx				// for calling compare
		push ebx				// for calling lower string
	_COPYNAME :
		mov dl, byte ptr[eax]
		mov byte ptr[ebx], dl	// copy name
		add ebx, 2
		add eax, 2
		cmp[eax], 0
		jnz _COPYNAME
		mov[ebx], 0
		call Lower				// lower dll name string
		push targetModule
		call __strcmpW			// compare dll name
		cmp al, 1
		jz _FOUND
		pop eax
		mov eax, [eax]			// next Flink
		jmp _LOOP				// if not found, go to next flink and loop again
	_FOUND :
		pop eax
		push DWORD ptr[eax + 18h]	// save dllBase
		pop dllBase
		mov foundModule, 1		// found target dll
	_END :
	}
	if (foundModule) {
		printf("\t[ok] Have found target module :)\n");
		printf("\t\tDllBase : %#x\n\t\tDll Name: %ws\n\n", dllBase, targetModule);
	}
	else
		printf("\t[no] Not found :(\n\n");

	return (HMODULE)dllBase;
}

func WINAPI GetProcByhMod(HMODULE hMod, WCHAR* procName) {

	PIMAGE_DOS_HEADER pIDH = NULL;		//DOS 头
	PIMAGE_NT_HEADERS pINH = NULL;		// NT头
	PIMAGE_DATA_DIRECTORY pIDD = NULL;	// 数据目录表
	PIMAGE_EXPORT_DIRECTORY pIED = NULL; // 导出表
	INT i = 0, length = 0;
	WORD ordinal = -1;
	DWORD funcAddr = NULL;

	WCHAR funcName[60] = { 0 };		// 函数名字
	CHAR *name = NULL;

	pIDH = (PIMAGE_DOS_HEADER)hMod;
	printf("[#]start Get Library By found module handle\n");

	if ((WORD)pIDH->e_magic == 0x5a4d)		// magic值 MZ
		printf("\tMatch \"MZ\" magic :)\n");
	else
		printf("\tNot Match \"MZ\" magic :(\n");

	pINH = (PIMAGE_NT_HEADERS)(pIDH->e_lfanew+(DWORD)hMod);
	/*
	printf("offset : %#x\n", pIDH->e_lfanew);
	printf("Image Base : %#x\n", hMod);
	printf("PIMAGE_NT_HEADERS value : %#x\n", pINH);
	*/
	if ((WORD)pINH->Signature == 0x4550)		// 签名 PE
		printf("\tMatch \"PE\" signature :)\n");
	else
		printf("\tNot Match \"PE\" signature :(\n");

	pIDD = (PIMAGE_DATA_DIRECTORY)((pINH->OptionalHeader).DataDirectory);	// 数据目录表
	pIED = (PIMAGE_EXPORT_DIRECTORY)(pIDD[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (DWORD)hMod);
	printf("\texport table VA : %#x\n\tfunction names array address : %#x\n", (DWORD)pIED, pIED->AddressOfNames + (DWORD)hMod);

	Lower(procName);	//

	for (i = 0; i < pIED->NumberOfNames; i++) {
		name = (CHAR*)(*((DWORD*)(pIED->AddressOfNames + (DWORD)hMod) + i) + (DWORD)hMod);
		for (length = 0; name[length]; length++);	// 函数名长度
		/*printf("==> %s\n", name);
		
			通过functionames数组获取下标，根据该下标（输出函数名表和输出序号表一一对应）在输出序号表
			获取函数地址表中的序号，将序号减去基数作为下标寻找到函数地址RVA。
		*/
		MultiByteToWideChar(CP_ACP, NULL, name, ++length, funcName, length);
		//printf("\tcompared function name : %ws\n", funcName);
		Lower(funcName);
		if (__strcmpW(procName, funcName)) {
			printf("\t[ok] succeedfound function name :)\n");
			ordinal = *((WORD*)(pIED->AddressOfNameOrdinals + (DWORD)hMod) + i);  // WORD
			printf("\t\tindex of target function : %#x\n\t\tordinal number : %#x\n\t\torinal base : %#x\n", i, ordinal, pIED->Base);
			funcAddr = *((DWORD*)(pIED->AddressOfFunctions + (DWORD)hMod) + (ordinal/* - pIED->Base加上之后不对*/)) + (DWORD)hMod;
			printf("\tGet function address : %#x\n", funcAddr);
			break;
		}
	}
	if (!funcAddr)
		printf("\t[no] not Found target function :(");
	return (func)funcAddr;
}

INT main(INT argc, CHAR* argv[]) {
	WCHAR searchMod[] = { L"Kernel32.dll" };
	WCHAR procLoadlib[] = { L"LoadLibraryA" };
	WCHAR procGetProc[] = { L"GetProcAddress" };

	//func procAddr = NULL;

	//
	CHAR tarMod[] = { "User32.dll" };
	CHAR targFunc[] = { "MessageBoxA" };	// 测试弹窗
	CHAR test[] = { "test" };/////

	/*HMODULE hMod = LoadLibraryA(tarMod);
	typedef int (*msgBoxProc)(HWND, LPCTSTR, LPCTSTR, UINT);
	msgBoxProc f = (msgBoxProc)GetProcAddress(hMod, targFunc);
	f(NULL, (LPCTSTR)"test", (LPCTSTR)"test", MB_OK);*/

	HMODULE hMod = FindModuleByPeb(searchMod);
	if (hMod) {
		__asm {
			lea eax, procLoadlib
			push eax	//LoadLibraryA
			push hMod
			call GetProcByhMod
			cmp eax, 0
			jz _END2
			mov ebx,eax
			lea eax, tarMod	// target mod; user32.dll
			push eax
			call ebx		// call LoadLibraryA
			cmp eax,0
			jz _END2
			push eax	// save hInstance value
			lea eax,procGetProc		// string GetProcAddress
			push eax
			push hMod
			call GetProcByhMod
			cmp eax, 0
			jz _END2
			mov ebx, eax
			lea eax, targFunc
			pop edx
			push eax	// messageboxa
			push edx	// target hMod
			call ebx		// call getprocaddress
			cmp eax, 0
			jz _END2
			mov ebx, eax
			push MB_OK
			lea eax, test
			push eax
			push eax
			push 0			// param for messagebox
			call ebx	// call got api - messageboxA
		_END2:
		}
	}
}

