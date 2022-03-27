#include "stdio.h"
#include "Winsock2.h"
#include "IPTypes.h"
#include "iphlpapi.h"

#pragma comment(lib, "Iphlpapi.lib")

typedef DWORD(*fDhcpIsEnabled)(PCWSTR, DWORD*);
fDhcpIsEnabled pDhcpIsEnabled = NULL;

typedef DWORD(*fDhcpReleaseParameters)(PCWSTR);
fDhcpReleaseParameters pDhcpReleaseParameters = NULL;

typedef DWORD(*fDhcpAcquireParameters)(PCWSTR);
fDhcpAcquireParameters pDhcpAcquireParameters = NULL;



DWORD GetAllInterfaceInfo(PIP_ADAPTER_ADDRESSES_LH &pIPAdapterAddr, ULONG family){

	ULONG SizePointer = 0;
	DWORD retStatus = 0;

	while (1)
	{
		retStatus = GetAdaptersAddresses(family, GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, 0, pIPAdapterAddr, &SizePointer);
		if (!retStatus)
			break;
		if (pIPAdapterAddr)
			LocalFree(pIPAdapterAddr);
		pIPAdapterAddr = 0;
		if (retStatus != ERROR_BUFFER_OVERFLOW)
			break;
		pIPAdapterAddr = (PIP_ADAPTER_ADDRESSES_LH)LocalAlloc(LMEM_ZEROINIT, SizePointer);
		if (!pIPAdapterAddr){
			retStatus = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
	}
	return retStatus;
}

BOOL ReleaseNetio(PIP_ADAPTER_ADDRESSES_LH pIPAdapterAddr) {

	if (!pIPAdapterAddr) return FALSE;

	PIP_ADAPTER_ADDRESSES_LH pos = pIPAdapterAddr;
	WCHAR InterfaceName[35] = { 0 };
	DWORD retStatus = 0, dhcpEnabled = 0;

	do {
		if (pos->IfType != IF_TYPE_SOFTWARE_LOOPBACK && pos->Flags & IP_ADAPTER_IPV4_ENABLED) {
			retStatus = ConvertInterfaceLuidToNameW(&pos->Luid, InterfaceName, 0x20);
			if (0 != retStatus) 
				continue;
			retStatus = pDhcpIsEnabled(InterfaceName, &dhcpEnabled);
			if (retStatus || !dhcpEnabled || pos->OperStatus == IfOperStatusDown)
				continue;
			pDhcpReleaseParameters(InterfaceName);
		}
	} while ((pos = pos->Next), pos);

	return TRUE;
}

BOOL RenewNetio(PIP_ADAPTER_ADDRESSES_LH pIPAdapterAddr) {

	if (!pIPAdapterAddr) return FALSE;

	PIP_ADAPTER_ADDRESSES_LH pos = pIPAdapterAddr;
	WCHAR InterfaceName[35] = { 0 };
	DWORD retStatus = 0, dhcpEnabled = 0;

	do {
		if (pos->IfType != IF_TYPE_SOFTWARE_LOOPBACK && pos->Flags & IP_ADAPTER_IPV4_ENABLED) {
			retStatus = ConvertInterfaceLuidToNameW(&pos->Luid, InterfaceName, 0x20);
			if (0 != retStatus)
				continue;
			retStatus = pDhcpIsEnabled(InterfaceName, &dhcpEnabled);
			if (!retStatus) {
				if (!dhcpEnabled || pos->OperStatus == IfOperStatusDown)
					continue;

			}
			pDhcpAcquireParameters(InterfaceName);
		}
	} while ((pos = pos->Next), pos);

	return TRUE;
}

INT main() {

	HMODULE hLib = LoadLibraryEx(L"dhcpcsvc.dll", 0, 0);

	if (!hLib) {
		printf("[x] LoadLibraryEx Failed , Error : %#x\n", GetLastError());
		return -1;
	}
	pDhcpIsEnabled = (fDhcpIsEnabled)GetProcAddress(hLib, "DhcpIsEnabled");
	if (!pDhcpIsEnabled) {
		printf("[x] Get DhcpIsEnabled Function Failed , Error : %#x\n", GetLastError());
		return -1;
	}
	pDhcpReleaseParameters = (fDhcpReleaseParameters)GetProcAddress(hLib, "DhcpReleaseParameters");
	if (!pDhcpReleaseParameters) {
		printf("[x] Get DhcpReleaseParameters Function Failed , Error : %#x\n", GetLastError());
		return -1;
	}
	pDhcpAcquireParameters = (fDhcpAcquireParameters)GetProcAddress(hLib, "DhcpAcquireParameters");
	if (!pDhcpAcquireParameters) {
		printf("[x] Get DhcpAcquireParameters Function Failed , Error : %#x\n", GetLastError());
		return -1;
	}
	// GetAllInterfaceInfo
	PIP_ADAPTER_ADDRESSES_LH pAdapterAddressInfo = NULL;
	DWORD64 retStatus = GetAllInterfaceInfo(pAdapterAddressInfo, 2);
	if (retStatus) {
		printf("[x] GetAllInterfaceInfo Failed , Error : %#x\n", GetLastError());
		return -1;
	}

	// release ipv4 adapter, network will disconnect
	if (!ReleaseNetio(pAdapterAddressInfo)) {
		printf("[x] ReleaseNetio FAILED, error : %#x\n", GetLastError());
		return -1;
	}
	printf("[+] DoReleaseNetio SUCCESS\n");

	printf("\n\n[-] Press ENTER to RENEW adapter...\n\n");
	getchar();

	// renew ipv4 adapter, network will reconnect
	if (!RenewNetio(pAdapterAddressInfo)) {
		printf("[x] RenewNetio FAILED, error : %#x\n", GetLastError());
		return -1;
	}
	printf("[+] RenewNetio SUCCESS\n");

	LocalFree(pAdapterAddressInfo);

	return 0;
}
