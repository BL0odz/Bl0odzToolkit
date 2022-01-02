/*
	使用重启管理器关闭指定资源的相关进程
*/

#include "windows.h"
#include "stdio.h"
#include "restartmanager.h"
#pragma comment(lib, "Rstrtmgr.lib")

LPCSTR getAppType(INT type) {

	if (1000 == type)
		return "RmCritical";

	LPCSTR appTypeArr[] = { "RmUnknownApp","RmMainWindow","RmOtherWindow","RmService","RmExplorer","RmConsole" };
	return appTypeArr[type];
}

LPCSTR getAppStatus(INT status) {
	LPCSTR appStatusArr[] = { "RmStatusUnknown", "RmStatusRunning", "RmStatusStopped", "RmStatusStoppedOther",
		"RmStatusRestarted", "RmStatusErrorOnStop", "RmStatusErrorOnRestart", "RmStatusShutdownMasked",
		"RmStatusRestartMasked" };
	int idx = 0;
	while (status) {
		status >>= 1;
		idx++;
	}
	return appStatusArr[idx];
}

void printRgAffectedAppsList(INT nProcInfo, RM_PROCESS_INFO *rgAffectedApps) {

	printf("%8s%35s%35s%20s%30s%15s%15s\n",
		"PID", "AppName", "ServiceShortName", "ApplicationType",
		"AppStatus", "TSSessionID", "RestartAble");
	// PID   AppName   ServiceName   ApplicationType   AppStatus   TSSessionID   RestartAble
	for (int i = 0; i < nProcInfo; i++) {
		printf("%8d", rgAffectedApps[i].Process.dwProcessId);	// pid
		printf("%35ws", rgAffectedApps[i].strAppName);		// appname
		printf("%35ws", rgAffectedApps[i].strServiceShortName);		// ServiceName
		printf("%20s", getAppType(rgAffectedApps[i].ApplicationType));		// ApplicationType
		printf("%30s", getAppStatus(rgAffectedApps[i].AppStatus));		// AppStatus
		printf("%15d", rgAffectedApps[i].TSSessionId);
		printf("%15s\n", rgAffectedApps[i].bRestartable ? "True" : "False");
	}
}

int main() {

	DWORD ret = -1, RMSessionHandle = -1;
	WCHAR pSessionKey[CCH_RM_SESSION_KEY + 2];

	UINT nFiles = 1, nApplications = 0, nServices = 0;
	LPCWSTR rgsFilenames[] = { L"C:\\Windows\\SysWOW64\\gpapi.dll" };	// 注册的文件资源
	PRM_UNIQUE_PROCESS rgsApplications = NULL;
	LPCWSTR *rgsServiceNames = NULL;

	UINT nProcInfoNeeded = 0, nProcInfo = 0;
	PRM_PROCESS_INFO rgAffectedApps = NULL;		// 接收正在使用注册资源的进程或服务列表，
												// 分配空间过小会报错ERROR_MORE_DATA，可根据nProcInfoNeeded申请内存
	//RM_PROCESS_INFO rgAffectedApps[30];
	DWORD dwRebootReasons = -1;			// 接收一个枚举值，表示是否需要系统重启，以及重启的理由

	// 启动一个新的重启管理器会话，每个用户只能同时开启64个重启管理器会话
	if (!(ret = RmStartSession(&RMSessionHandle, 0, pSessionKey))) {
		printf("[SUCCESS] 启动重启管理器会话成功...\n");
		if (!(ret = RmRegisterResources(RMSessionHandle,
			nFiles, rgsFilenames,
			nApplications, rgsApplications,
			nServices, rgsServiceNames))) {
			printf("[SUCCESS] 注册资源成功...\n");
			ret = RmGetList(RMSessionHandle, &nProcInfoNeeded, &nProcInfo, rgAffectedApps, &dwRebootReasons);
			if (ERROR_MORE_DATA == ret) {
				ret = -1;
				printf("\t需要结构体 RM_PROCESS_INFO %d 个...\n", nProcInfoNeeded);
				rgAffectedApps = new RM_PROCESS_INFO[nProcInfoNeeded + 1];
				
				nProcInfo = nProcInfoNeeded;	// 重点，这里需要注意一下，要指定接收的结构体数量
				memset(rgAffectedApps, 0, sizeof(rgAffectedApps));
				
				if (!(ret = RmGetList(RMSessionHandle,
					&nProcInfoNeeded, &nProcInfo,
					rgAffectedApps, &dwRebootReasons))) {
					printf("[SUCCESS] 获取受影响进程（服务）列表成功...\n\t列表如下:\n");
					printRgAffectedAppsList(nProcInfo, rgAffectedApps);
					ret = -1;
					if (!(ret = RmShutdown(RMSessionHandle, 0, NULL))) {
						printf("[SUCCESS] 调用RmShutDown关闭占用注册资源的进程（服务）成功...\n");
					}
					else
						printf("[FAILED] RmShutDown调用失败 %d!!!\n", ret);
				}
				else
					printf("[FAILED] 获取受影响进程（服务）列表失败 %d!!!\n", ret);
				free(rgAffectedApps);
				rgAffectedApps = NULL;
			}
		}
		else
			printf("[FAILED] 注册资源失败 %d!!!\n", ret);
		RmEndSession(RMSessionHandle);
	}
	else
		printf("[FAILED] 启动重启管理器会话失败 %d!!!\n", ret);
	return 0;
}
