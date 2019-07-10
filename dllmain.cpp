// dllmain.cpp : 定義 DLL 應用程式的進入點。
#include "pch.h"

#include <stdlib.h>

#include "XFSAPI.H"
#include "XFSIDC.H"
#include "XFSPIN.H"

char* MemLand[] =
{
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	(char*)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
};

ULONG InputPinKeys[] =
{
	WFS_PIN_FK_0,
	WFS_PIN_FK_1,
	WFS_PIN_FK_2,
	WFS_PIN_FK_3,
	WFS_PIN_FK_4,
	WFS_PIN_FK_5,
	WFS_PIN_FK_6,
	WFS_PIN_FK_7,
};

HRESULT extern __stdcall WFSStartUp(DWORD dwVersionsRequired, LPWFSVERSION lpWFSVersion)
{
	lpWFSVersion->wVersion = 3;
	lpWFSVersion->wLowVersion = 1;
	lpWFSVersion->wHighVersion = 1;
	memcpy(lpWFSVersion->szDescription, "Fake msxfs.dll", 14);

	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSExecute(HSERVICE hService, DWORD dwCommand, LPVOID lpCmdData, DWORD dwTimeOut, LPWFSRESULT* lppResult)
{
	(*lppResult) = (WFSRESULT*)malloc(sizeof(WFSRESULT));

	if (!(*lppResult))
		return WFS_ERR_INTERNAL_ERROR;

	(*lppResult)->u.dwCommandCode = dwCommand;
	(*lppResult)->hService = 0x1234;
	(*lppResult)->RequestID = 0;
	(*lppResult)->hResult = WFS_SUCCESS;
	(*lppResult)->lpBuffer = MemLand;

	if (dwCommand == WFS_CMD_PIN_GET_DATA)
	{
		LPWFSPINDATA buffer = (LPWFSPINDATA)((*lppResult)->lpBuffer = malloc(sizeof(WFSPINDATA)));
		if (!buffer)
			return WFS_ERR_INTERNAL_ERROR;

		USHORT keyLen = sizeof(InputPinKeys) / sizeof(ULONG);

		buffer->usKeys = keyLen;
		buffer->wCompletion = 0;
		buffer->lpPinKeys = (LPWFSPINKEY*)malloc(sizeof(LPWFSPINKEY) * keyLen);
		if (!buffer->lpPinKeys)
			return WFS_ERR_INTERNAL_ERROR;

		for (int i = 0; i < keyLen; i++) {
			WFSPINKEY* PinKey = (WFSPINKEY*)(buffer->lpPinKeys[i] = (WFSPINKEY*)malloc(sizeof(WFSPINKEY)));
			if (!PinKey)
				return WFS_ERR_INTERNAL_ERROR;

			PinKey->ulDigit = InputPinKeys[i];
			PinKey->wCompletion = 0;
		}

		return WFS_SUCCESS;
	}
	else if (dwCommand == WFS_CMD_IDC_READ_RAW_DATA)
	{
		LPWFSIDCCARDDATA* array = (LPWFSIDCCARDDATA*)((*lppResult)->lpBuffer = malloc(sizeof(LPWFSIDCCARDDATA) * 2));
		if (!array)
			return WFS_ERR_INTERNAL_ERROR;

		LPWFSIDCCARDDATA buffer = array[0] = (LPWFSIDCCARDDATA)malloc(sizeof(WFSIDCCARDDATA));
		if (!buffer)
			return WFS_ERR_INTERNAL_ERROR;

		buffer->wDataSource = WFS_IDC_TRACK2;
		buffer->wStatus = WFS_IDC_DATAOK;
		buffer->ulDataLength = 12;
		buffer->lpbData = (BYTE*)malloc(sizeof(BYTE) * 13);
		if (!buffer->lpbData)
			return WFS_ERR_INTERNAL_ERROR;

		memcpy(buffer->lpbData, "A1234567890B", 13);
		buffer->wDataSource = WFS_IDC_TRACK2;
		buffer->fwWriteMethod = 0;

		array[1] = 0;

		return WFS_SUCCESS;
	}

	return WFS_ERR_INTERNAL_ERROR;
}

HRESULT extern __stdcall WFSOpen(LPSTR lpszLogicalName, HAPP hApp, LPSTR lpszAppID, DWORD dwTraceLevel, DWORD dwTimeOut, DWORD dwSrvcVersionsRequired, LPWFSVERSION lpSrvcVersion, LPWFSVERSION lpSPIVersion, LPHSERVICE lphService)
{
	*lphService = 1;
	lpSPIVersion->wVersion = 3;
	lpSPIVersion->wLowVersion = 1;
	lpSPIVersion->wHighVersion = 1;
	memcpy(lpSrvcVersion->szDescription, "Fake WFSOpen()", 14);

	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSGetInfo(HSERVICE hService, DWORD dwCategory, LPVOID lpQueryDetails, DWORD dwTimeOut, LPWFSRESULT* lppResult)
{
	(*lppResult) = (LPWFSRESULT)malloc(sizeof(WFSRESULT));
	if (!(*lppResult))
		return WFS_ERR_INTERNAL_ERROR;

	(*lppResult)->u.dwCommandCode = dwCategory;
	(*lppResult)->hService = 0x1234;
	(*lppResult)->RequestID = 0;
	(*lppResult)->hResult = WFS_SUCCESS;
	(*lppResult)->lpBuffer = MemLand;

	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSFreeResult(LPWFSRESULT lpResult)
{
	if (lpResult->u.dwCommandCode == WFS_CMD_PIN_GET_DATA)
	{
		WFSPINDATA* buffer = (WFSPINDATA*)lpResult->lpBuffer;

		USHORT keyLen = sizeof(InputPinKeys) / sizeof(ULONG);

		for (int i = keyLen - 1; i >= 0; i--)
			free(buffer->lpPinKeys[i]);
		free(buffer->lpPinKeys);
		free(lpResult->lpBuffer);
	}

	free(lpResult);

	return WFS_SUCCESS;
}

BOOL extern __stdcall WFSIsBlocking()
{
	return FALSE;
}

HRESULT extern __stdcall WFSClose(HSERVICE hService)
{
	return WFS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////

HRESULT extern __stdcall WFSCancelAsyncRequest(HSERVICE hService, REQUESTID RequestID)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSCancelBlockingCall(DWORD dwThreadID)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSCleanUp()
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSAsyncClose(HSERVICE hService, HWND hWnd, LPREQUESTID lpRequestID)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSCreateAppHandle(LPHAPP lphApp)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSDeregister(HSERVICE hService, DWORD dwEventClass, HWND hWndReg)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSAsyncDeregister(HSERVICE hService, DWORD dwEventClass, HWND hWndReg, HWND hWnd, LPREQUESTID lpRequestID)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSDestroyAppHandle(HAPP hApp)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSAsyncExecute(HSERVICE hService, DWORD dwCommand, LPVOID lpCmdData, DWORD dwTimeOut, HWND hWnd, LPREQUESTID lpRequestID)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSAsyncGetInfo(HSERVICE hService, DWORD dwCategory, LPVOID lpQueryDetails, DWORD dwTimeOut, HWND hWnd, LPREQUESTID lpRequestID)
{
	return WFS_SUCCESS;
}

SCODE extern __stdcall WFSGetSCode(HRESULT hResult)
{
	return 0;
}

HRESULT extern __stdcall WFSLock(HSERVICE hService, DWORD dwTimeOut, LPWFSRESULT* lppResult)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSAsyncLock(HSERVICE hService, DWORD dwTimeOut, HWND hWnd, LPREQUESTID lpRequestID)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSAsyncOpen(LPSTR lpszLogicalName, HAPP hApp, LPSTR lpszAppID, DWORD dwTraceLevel, DWORD dwTimeOut, LPHSERVICE lphService, HWND hWnd, DWORD dwSrvcVersionsRequired, LPWFSVERSION lpSrvcVersion, LPWFSVERSION lpSPIVersion, LPREQUESTID lpRequestID)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSRegister(HSERVICE hService, DWORD dwEventClass, HWND hWndReg)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSAsyncRegister(HSERVICE hService, DWORD dwEventClass, HWND hWndReg, HWND hWnd, LPREQUESTID lpRequestID)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSSetBlockingHook(XFSBLOCKINGHOOK lpBlockFunc, LPXFSBLOCKINGHOOK lppPrevFunc)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSUnhookBlockingHook()
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSUnlock(HSERVICE hService)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFSAsyncUnlock(HSERVICE hService, HWND hWnd, LPREQUESTID lpRequestID)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFMSetTraceLevel(HSERVICE hService, DWORD dwTraceLevel)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFMAllocateBuffer(ULONG ulSize, ULONG ulFlags, LPVOID* lppvData)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFMAllocateMore(ULONG ulSize, LPVOID lpvOriginal, LPVOID* lppvData)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFMFreeBuffer(LPVOID lpvData)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFMGetTraceLevel(HSERVICE hService, LPDWORD lpdwTraceLevel)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFMKillTimer(WORD wTimerID)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFMMakeResult(SCODE SCode)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFMOutputTraceData(LPSTR lpszData)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFMReleaseDLL(HPROVIDER hProvider)
{
	return WFS_SUCCESS;
}

HRESULT extern __stdcall WFMSetTimer(HWND hWnd, LPVOID lpContext, DWORD dwTimeVal, LPWORD lpwTimerID)
{
	return WFS_SUCCESS;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

