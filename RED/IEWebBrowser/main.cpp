#include "windows.h"
#include "mshtml.h"
#include "stdio.h"
#include "ExDisp.h"
#include "atlbase.h"
#include "comutil.h"
#include "oleacc.h"

//#pragma comment(lib, "oleacc.lib")

//int WINAPI WinMain(HINSTANCE hins, HINSTANCE hPrev, LPSTR lpCmdLine, INT nCmdShow) {
INT main(int argc, char* argv[]){
	//IWebBrowser2 
	HWND hWnd_pre = NULL, hWnd_child = NULL, hWnd_IES = NULL;
	hWnd_pre = FindWindow("IEFrame", NULL);	//IE Window Class
	if (hWnd_pre == NULL) {
		OutputDebugString(TEXT("IE didnot open."));
	}

	hWnd_child = FindWindowEx(hWnd_pre, 0, TEXT("Shell DocObject View"), NULL);	// test
	if (hWnd_child == NULL) {	// not only three Layers
		hWnd_child = FindWindowEx(hWnd_pre, 0, TEXT("Frame Tab"), NULL);
		if (hWnd_child == NULL) {
			OutputDebugString(TEXT("not Found IE Tab."));
		}
		hWnd_pre = hWnd_child;
		hWnd_child = FindWindowEx(hWnd_pre, 0, TEXT("TabWindowClass"), NULL);
		hWnd_pre = hWnd_child;
		hWnd_child = FindWindowEx(hWnd_pre, 0, TEXT("Shell DocObject View"), NULL);
		hWnd_pre = hWnd_child;
		hWnd_child = FindWindowEx(hWnd_pre, 0, TEXT("Internet Explorer_Server"), NULL);
	}
	else {
		hWnd_pre = hWnd_child;
		hWnd_child = FindWindowEx(hWnd_pre, 0, TEXT("Internet Explorer_Server"), NULL);
	}
	hWnd_IES = hWnd_child;		// Get Internet Explorer_Server Window's Handle
	printf("handle value of Internet Explorer_Server => %#x\n", (DWORD*)hWnd_child);

	CoInitialize(0);   // for using of COM interfaces
	UINT nMsg = RegisterWindowMessage(TEXT("WM_HTML_GETOBJECT"));   // register common msg of between two windows
	if (nMsg)
		printf("success registe Window message WM_HTML_GETOBJECT, msg ID => %#x\n", nMsg);
	
	CComPtr<IHTMLDocument2> pHtmlDoc;
	LRESULT result;
	//if (!SendMessageTimeout(hWnd_IES, nMsg, 0, 0, SMTO_NORMAL, 30000, (LPDWORD)result)) {
	if (!(result = SendMessage(hWnd_IES, nMsg, 0, 0)))		// send message for associated value of msg
		printf("call sendMessageTimeout failed:( error code: %#x\n", GetLastError());
	else {
		printf("returned result value: %#x\n", result);
		/*if (!result) {
			printf("returned result id none...end");
			ExitProcess(1);
		}*/
		HMODULE hLib = LoadLibrary("oleacc.dll");
		LPFNOBJECTFROMLRESULT pFObjectFromLresult = (LPFNOBJECTFROMLRESULT)GetProcAddress(hLib, "ObjectFromLresult");
		//HRESULT hRes = ObjectFromLresult(result, IID_IHTMLDocument2, 0, (void**)&pHtmlDoc);
		HRESULT hRes = pFObjectFromLresult(result, IID_IHTMLDocument2, 0, (void**)&pHtmlDoc);
		if (SUCCEEDED(hRes)) {
			printf("get IHTMLDocument2 success :)\n");
			//OLECHAR urll[] = L"http://www.baidu.com/";
			CComPtr<IHTMLWindow2> spWnd2;
			CComPtr<IServiceProvider> spServiceProvider;
			IWebBrowser2* pWebBrow = NULL;
			hRes = pHtmlDoc->get_parentWindow((IHTMLWindow2**)&spWnd2);
			if (SUCCEEDED(hRes)) {
				hRes = spWnd2->QueryInterface(IID_IServiceProvider, (void**)&spServiceProvider);	// Query Interface
				if (SUCCEEDED(hRes)) {
					hRes = spServiceProvider->QueryService(IID_IWebBrowserApp, IID_IWebBrowser2, (void**)&pWebBrow);   // query service
					if (SUCCEEDED(hRes)) {
						printf("Get IWebBrowser handlw Success :)\n");

						////1-跳转测试
						//VARIANT PARAM;
						//VariantInit(&PARAM);
						////V_VT(&PARAM) = VT_I4;
						////V_I4(&PARAM) = navOpenInNewTab;	//open in new tab
						////hRes = pWebBrow->Navigate2(&CComVariant("http://www.baidu.com/"), 0, 0, 0, 0);// win7 and former versions not support.
						//BSTR URLL = SysAllocString(L"http://www.baidu.com/");
						//hRes = pWebBrow->Navigate(URLL, &PARAM, &PARAM, &PARAM, &PARAM);		// navigate
						//SysFreeString(URLL);
						//if (SUCCEEDED(hRes)) printf("navigate success :)\n");
						//else printf("navigate failed :(\n");
						
						///*//2-获取地址栏URL测试
						//hRes = pWebBrow->get_LocationURL(&URLLL);
						//if(SUCCEEDED(hRes))
						//	printf("Get URL : %ws\n", URLL);*/
						
						////3-write document
						//SAFEARRAY* pSafeArr = SafeArrayCreateVector(VT_VARIANT, 0, 1);
						//if (pSafeArr) {
						//	BSTR pInsertCode = SysAllocString(L"<script>alert('just a test')</script>");
						//	VARIANT *PARAM = NULL;
						//	SafeArrayAccessData(pSafeArr, (void**)&PARAM);
						//	V_VT(PARAM) = VT_BSTR;		// PARAM->vt = VT_BSTR
						//	V_BSTR(PARAM) = pInsertCode;	// PARAM->bStrVal
						//	SafeArrayUnaccessData(pSafeArr);
						//	pHtmlDoc->write(pSafeArr);	// will refresh
						//	pHtmlDoc->close();
						//	SafeArrayDestroy(pSafeArr);
						//	pSafeArr = NULL;
						//}
						

						//get HTML codes
						BSTR pText = SysAllocString(L"<script>alert('test')</script>");
						BSTR wheer = SysAllocString(L"afterBegin");	//代码放置位置
						CComPtr<IHTMLElement> pHtmlElem;
						pHtmlDoc->get_body(&pHtmlElem);
						
						//pHtmlElem->get_innerHTML(&pText);
						//pHtmlElem->put_innerHTML(pText);
						hRes = pHtmlElem->insertAdjacentHTML(wheer, pText); // 插入
						SysFreeString(pText);
						SysFreeString(wheer);
						pText = NULL;
						wheer = NULL;

						//重载页面
						if (SUCCEEDED(hRes)) {
							printf("insert html code SUCCESS:)\n");

							/*pHtmlElem->get_outerHTML(&pText);
							SAFEARRAY* pSafeArr = SafeArrayCreateVector(VT_VARIANT, 0, 1);
							VARIANT *PARAM = NULL;
							SafeArrayAccessData(pSafeArr, (void**)&PARAM);
							V_VT(PARAM) = VT_BSTR;
							V_BSTR(PARAM) = pText;
							SafeArrayUnaccessData(pSafeArr);
							pHtmlDoc->write(pSafeArr);
							pHtmlDoc->close();
							SafeArrayDestroy(pSafeArr);
							pSafeArr = NULL;*/
						}
						else
							printf("insert html code Failed:(\n");
						//printf("HTML Text (length: %#x): %ws\n", );
						//INT dwSize = wcslen(pText);
						//CHAR *pOutter = (CHAR*)malloc(dwSize);
						//WideCharToMultiByte(CP_ACP, 0, pText, dwSize, pOutter, dwSize, 0, 0);
						//FILE *fp = fopen("html.html", "w");
						////fprintf(fp, "%ws", pText);
						//fwrite(pOutter, wcslen(pText), 1, fp);
						//free(pOutter);
						//fclose(fp);

					}
					else printf("Get IWebBrowser handle Failed:(\n");
				}
				//pHtmlDoc->get_body(&pHtmlElem); //get_body(&pHtmlElem);
				//pHtmlElem->get_outerHTML(pText); //get_innerText(pText);
				//printf("GOT > \n%ws\n", pText);
				pWebBrow->Release();
				pWebBrow = NULL;
			}
			else
				printf("error returned Result Code: %#x\n", hRes);
		}
		else printf("get IHTMLDocument2 failed:(\n");
	}
	/*printf("%#x\n", hwd);

	PostMessage(hWnd_IES, WM_QUIT, 0, 0);
	PostMessage(hWnd_IES, WM_CLOSE, 0, 0);
	PostMessage(hWnd_IES, WM_DESTROY, 0, 0);*/
	/*CoUninitialize(); //添加则出现异常，可能是在程序退出时还会调用一次析构函数，以释放所有声明的变量
	ExitProcess(0);*/
}
