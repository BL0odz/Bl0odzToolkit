#include "stdio.h"
#include "Windows.h"

int main() {

	HANDLE hEvtObj = NULL;
	DWORD hRet = NULL;
	CHAR objName[] = { "ObjTestEvt_123" };

	if (hEvtObj = CreateEventA(
		NULL, 
		TRUE,		// 手动重置为非信号态 
		FALSE,		// 初始不可响应 
		objName)) 
	{
		if (ERROR_ALREADY_EXISTS == GetLastError()) { // 事件对象已存在
			printf("Event Obj \"%s\" has EXISTED ...\n", objName);
			for (int i = 0; i < 10;) {			// 响应10次
				hRet = WaitForSingleObject(hEvtObj, 300);	// 超时时间为0.3秒
				if (!hRet) {
					printf("\"%s\" is now SIGNALED %d\n", objName, i++);	// 信号态
				}
				else {
					if (WAIT_TIMEOUT == hRet)
						printf("\"%s\" is now NONSIGNALED\n", objName);		// 非信号态
					else
						printf("Wait Error %#x...\n", GetLastError());
				}
				Sleep(1000);	// 休眠一秒
			}
		}
		else {	// 成功创建事件对象
			printf("Create Evt Obj \"%s\" Successful\n", objName);
			Sleep(1000);		// 等待同步进程运行
			printf("Set Event \"%s\" To SIGNALED  for 4 seconds...\n", objName);
			SetEvent(hEvtObj);		// 设置为事件对象为信号态
			Sleep(4000);			// 休眠4s
			printf("Reset Event \"%s\" To NONSIGNALED for 4 seconds...\n", objName);
			ResetEvent(hEvtObj);	// 设置为非信号态
			Sleep(4000);			// 让事件对象处于非信号态4s
			printf("Set Event \"%s\" To SIGNALED...\n", objName);
			SetEvent(hEvtObj);		//
		}
		CloseHandle(hEvtObj);
		hEvtObj = NULL;
	}
	else {	// 创建失败
		printf("CreateEvent Error = %#x", GetLastError());
	}

	return 0;
}
