/*
各虚拟机探测方法
*/

//#include "windows.h"
#include "stdio.h"
#include "Winsock2.h"
#include "IPHlpapi.h"
#include "tlhelp32.h"
#pragma comment(lib, "iphlpapi.lib")  // GetAdaptersAddresses

/* 
通过执行特权指令探测Vmware 
因为在虚拟机中指定功能号0xa则会从指定端口获取虚拟机版本信息到指定的目的操作数地址
另外0x14则是获取虚拟机内存大小，当获取的值大于0说明在虚拟机中*/
BOOL detectVmwareByPrivilegeAsmInstruction() {

	BOOL rv = FALSE;
	//DWORD val = 0, val_1 = 0;
	__try {
		__asm {
			pushad
			mov eax, 'VMXh'	// magic value
			mov ebx, 1		// 设置未非'VMXh'值，接收in指令的返回值（VMware 版本）
			// 如果程序运行在虚拟机中，magic值将被移至ebx中
			// https://www.aldeid.com/wiki/VMXh-Magic-Value
			mov ecx, 0ah	//功能号
			mov edx, 'VX'	//端口号
			in eax, dx
			/*mov val, eax
			mov val_1, ebx*/
			cmp ebx, 'VMXh'
			setz [rv]
			popad
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {	// 不在虚拟机中则触发异常
		rv = FALSE;
	}
	//printf_s("%#x   %#x\n", val, val_1);
	return rv;
}

/*
通过IDT基址来判断虚拟机,
RedPill作者发现在Vmware虚拟机上的IDT地址高字节通常为0xff；VirtualPC则是0ze8；
在真是主机上通常为0x80。因此redpill利用判断执行SIDT指令后返回的第一个字节是否大于0xd0来确定是否程序是否运行于虚拟机中
typedef struct
{
	WORD IDTLimit;		// IDT的大小
	WORD LowIDTbase;	// IDT的低位地址
	WORD HiIDTbase;		// IDT的高位地址
} IDTINFO;
但是需满足机器上只有一个处理器，多核
而且经过测试似乎对于最近版本VMware(测试环境是VM 12.0，Winxp sp3)无效*/
BOOL detectVmByIDTBaseAddr() {
	/*\x0f\x01\x0d为sidt指令，\xc3 为 ret;相当于
	sidt[pos]
	retn*/
	unsigned char m[2+4], rpill[] = "\x0f\x01\x0d\x00\x00\x00\x00\xc3";
	*((unsigned*)&rpill[3]) = (unsigned)m;	// 设置读取的 sidt 地址保存位置地址
	DWORD oldProtec = NULL;
	VirtualProtect(rpill, sizeof(rpill), PAGE_EXECUTE_READWRITE, &oldProtec);
	((void(*)())&rpill)();	//执行 rpill 指令
	VirtualProtect(rpill, sizeof(rpill), oldProtec, &oldProtec);

	printf_s("\tidt base address: %#x\n", *(DWORD*)&m[2]);	// idt前两个字节为idt大小
	if (m[5] > 0xd0)
		return TRUE;
	return FALSE;
}

/*虚拟机中的GDT(全局描述表)和LDT(本地描述表)与这真实主机中的基址并不相同
可以通过SGDT和SLDT指令获取；
LDT基址位于0x0000(两个字节)时为真实主机，否则为虚拟机；GDT位于0xffxxxxxx(四个字节)说明位于虚拟机中，反之真实主机*/
BOOL detectVmByGDTAndLDTBaseAddr() {
	INT cnt = 0;

	/*LDT
	经过测试，目前的方法得到的值 LDT base 同样为0x0000，所以无效*/
	WORD ldtBase = 0;
	__asm sldt ldtBase
	printf("\tLDT base address: %#x\n", ldtBase);
	if (ldtBase)
		cnt++;

	/*GDT
	同样无效*/
	CHAR gdt[6];
	__asm sgdt gdt
	DWORD gdtBase = *(unsigned int*)&gdt[2];
	printf("\tGDT base address: %#x\n", gdtBase);
	if (gdt[2] == 0xff)
		cnt++;

	if (cnt > 0)
		return TRUE;
	
	return FALSE;
}

/*
通过STR指令获取TSS（task state segment）的段选择器；虚拟机中，读取的地址往往为0x0040xxxx，
否则为真实主机*/
BOOL detectVmBySTRGetTSSbase() {
	
	char tssSeg[4] = { 0 };

	/*测试无效*/
	__asm str tssSeg
	printf("\tGet base address base address: 0x");
	for (int i = 0; i < 4; i++)
		printf("%02x", tssSeg[i]);
	printf("\n");

	if(tssSeg[0] == 0x00 && tssSeg[1] == 0x40)
		return TRUE;
	return FALSE;
}

/*
通过在注册表中查找和VMware的虚拟硬件或VMwareTools等相关表项进行判别，
可以通过在注册表中搜索VMware或VMware Tool等关键词查找路径*/
BOOL detectVmByReg() {

	/*测试HKEY_CLASSES_ROOT\Applications\VMwareHostOpen.exe项*/
	HKEY phKey;
	if (ERROR_SUCCESS == RegOpenKey(HKEY_CLASSES_ROOT, L"Applications\\VMwareHostOpen.exe", &phKey))
		return TRUE;

	return FALSE;
}

/*
由于指令在虚拟机中执行速度远远不如宿主机中的，可以根据指令执行的时间差来识别；
通过 'rdtsc' 指令可以将计算机启动以来的CPU运行周期（ time-stamp counter）读至edx:eax；
 time-stamp counter存在一个64-bit MSR中。
 获取之后，高32 bits放入edx，低32 bits则是在eax中。
 比如xchg指令，在宿主机中测试运行之后明显远远小于在虚拟机中的时间*/
BOOL detectVmByTimeInterval() {

	BOOL retu = FALSE;
	CHAR prin[] = "\ttime interval： %#x\n";
	__asm {
		pushad
		rdtsc
		xchg eax, ecx
		rdtsc
		sub eax, ecx
		push eax
		push eax
		lea edx, prin
		push edx
		call ds:printf
		add esp, 0x8
		pop eax
		cmp eax, 0xff
		popad
		jb BACK
		mov retu, 1
	}
BACK:
	return retu;
}

/*
mac地址的前3个字节标识网络硬件制造商；
相同虚拟机软件中虚拟机的mac地址往往是相同的或者不变的，可以根据这个来识别虚拟机*/
BOOL detectVmByMacAddress() {
	BOOL flag = FALSE;
	CHAR buff[20] = { 0 };
	CONST ULONG MAX_TIMES = 3;

	ULONG family = AF_UNSPEC;	// both ipv4 and ipv6
	ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
	ULONG size = (ULONG)sizeof(IP_ADAPTER_ADDRESSES);
	PIP_ADAPTER_ADDRESSES pAdapterAddress = NULL;

	ULONG val = 0, ite = 0;
	do {
		pAdapterAddress = (PIP_ADAPTER_ADDRESSES)malloc(size);
		if (pAdapterAddress == NULL) {
			printf("Alloc Memory Failed!\n");
			return FALSE;
		}
		val = GetAdaptersAddresses(family, flags, 0, pAdapterAddress, &size);

		if (val == ERROR_BUFFER_OVERFLOW) {
			free(pAdapterAddress);
			pAdapterAddress = NULL;
		}
	} while ((val == ERROR_BUFFER_OVERFLOW) && (ite++<MAX_TIMES));
	/*尝试一定次数，可能跟会出现分配空间不足，见https://docs.microsoft.com/zh-cn/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses#parameters*/

	if (val == ERROR_SUCCESS) {
		ite = 0;
		while(pAdapterAddress){
			printf_s("\tAdapter #%d MAC addr：", ite);
			if (pAdapterAddress->PhysicalAddressLength != 0) {
				sprintf_s(buff, "%02x-%02x-%02x-%02x-%02x-%02x", pAdapterAddress->PhysicalAddress[0],
					pAdapterAddress->PhysicalAddress[1], pAdapterAddress->PhysicalAddress[2], 
					pAdapterAddress->PhysicalAddress[3], pAdapterAddress->PhysicalAddress[4], 
					pAdapterAddress->PhysicalAddress[5]);
				if (!wcsstr(pAdapterAddress->Description, L"VMnet")) {	// 排除可能是宿主机中虚拟网卡的情况
					printf_s("%s", buff);
					buff[8] = 0;
					if (!strcmp(buff, "00-05-69") || !strcmp(buff, "00-0c-29") || !strcmp(buff, "00-50-56") || /*VMware*/
						!strcmp(buff, "00-03-ff") ||  /*VirtualPC*/
						!strcmp(buff, "08-00-27")  /*VirtualBox*/
						) { 
						flag = TRUE;
					}
				}
				else printf("VmNet");
				printf_s("\n");
			}
			else printf_s("\n");
			pAdapterAddress = pAdapterAddress->Next;
			ite++;
		}
	}
	else {
		free(pAdapterAddress);
		pAdapterAddress = NULL;
	}
	return flag;
}

/*
通过判断Vm相关的进程进行判断，比如Vmware中的vmtoolsd.exe，
但是有时候进程并未在执行可能无法获取*/
BOOL detectVmByVMProcess() {

	BOOL flag = FALSE;
	WCHAR detecProc[] = L"vmtoolsd.exe";
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = NULL;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf_s("\tCreateToolhelp32Snapshot Failed!!");
		return FALSE;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32); //调用前必须设置结构体中的dwSize为PROCESSENTRY32结构体的大小
	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (!wcscmp(pe32.szExeFile, detecProc)) {
				printf_s("\trunning process：%ws\n", pe32.szExeFile);
				flag = TRUE;
				break;
			}
			//printf_s("\t%ws\n", pe32.szExeFile);
		} while (Process32Next(hSnapshot, &pe32));
	}
	CloseHandle(hSnapshot);
	return flag;
}

int main(int argc, char* argv[]) {

	BOOL flag = FALSE;

	/*通过执行特权指令实现探测 vmware*/
	printf("== detect by run `in` I/O instruction:\n");
	if (flag = detectVmwareByPrivilegeAsmInstruction())
		printf("\t\t[yes] detect vmware !\n\n");
	else 
		printf("\t\t[no] nothing found !\n\n");

	flag = false;
	/*使用idt基址检测虚拟机*/
	printf("=[x][invalid method now]= detect by retrieve idt base:\n");
	if (flag = detectVmByIDTBaseAddr()) 
		printf("\t\t[yes] detected vm !\n\n");
	else 
		printf("\t\t[no] nothing found !\n\n");

	flag = false;
	/*根据GDT和LDT基址检测虚拟机*/
	printf("=[x][invalid method now]= detect by retrieve idt base:\n");
	if (flag = detectVmByGDTAndLDTBaseAddr())
		printf("\t\t[yes] detected vm !\n\n");
	else
		printf("\t\t[no] nothing found !\n\n");

	flag = false;
	/*运行STR（非特权）指令，获取TR(任务寄存器)中的端选择器，虚拟机和真实主机之间是不同的。
	当地址等于0x0040xxxx时，说明处于虚拟机中；否则为真实主机*/
	printf("=[x][invalid method now]= detect by retrieve TSS base:\n");
	if (flag = detectVmBySTRGetTSSbase())
		printf("\t\t[yes] detected vm !\n\n");
	else
		printf("\t\t[no] nothing found !\n\n");

	flag = false;
	/*通过检测虚拟机注册表和Vmware相关的表项判别*/
	printf("== detect by register:\n");
	if (flag = detectVmByReg())
		printf("\t\t[yes] detected vm !\n\n");
	else
		printf("\t\t[no] nothing found !\n\n");

	flag = false;
	/*由于指令在虚拟机中执行速度远远不如宿主机中的，可以根据此来识别*/
	printf("== detect by instruction execute interval:\n");
	if (flag = detectVmByTimeInterval())
		printf("\t\t[yes] detected vm !\n\n");
	else
		printf("\t\t[no] nothing found !\n\n");

	flag = false;
	/*通过虚拟机mac地址的前3字节（网络硬件制造商编号）进行判别*/
	printf("== detect by MAC address:\n");
	if (flag = detectVmByMacAddress())
		printf("\t\t[yes] detected vm !\n\n");
	else
		printf("\t\t[no] nothing found !\n\n");

	flag = false;
	/*通过进程中是否有VM相关进程在执行，进行判别*/
	printf("== detect by Vm process:\n");
	if (flag = detectVmByVMProcess())
		printf("\t\t[yes] detected vm !\n\n");
	else
		printf("\t\t[no] nothing found !\n\n");

	return 0;
}
