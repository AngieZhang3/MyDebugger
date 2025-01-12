// MyDebugger.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "MyDebugger.h"
#define _WIN32_WINNT _WIN32_WINNT_WINXP    

bool g_IsSystemBreakPoint = true;

LPVOID g_lpDisAddr = NULL;

LPVOID g_lpBpAddress = NULL;
LPVOID g_lpShowMemAddr = NULL; // address for displaying memory

UINT   g_nBpType = 0;  // 1 = one-time bp 2= permenant bp
BYTE  g_OldCode = 0;

bool  g_IsBpStep = false;
bool  g_IsHardStep = false;
bool  g_IsStep = false;
bool  g_IsMemStep = false;

// software bp
std::list<SoftBp> g_softBp;

//memory breakpoint
DWORD g_nMemOldProto;  //old memory protection option
LPVOID g_lpMemAddress;   //memory bp address
UINT g_nMemSize;				// memory bp size
char g_chMemType;			// memory bp type

std::list<MemBp> g_memBps; // list of memory bp 
std::list<PageInfo> g_pages; // list of pages 
std::list<BpPageMapping> g_bpPageMappings; // list of bp-page mapping
DWORD g_nBmpIdCount = 0; // create Id for bps;

//page info:  ((Address+Size) & 0xfffff000)- (Address &0xfffff000)
/*
* 00401fff + 2 => 00402000 - 00401000 = 0x1000
*/

//Hardware bp
HardBp g_HardBp[4];
int    g_nCount = 0;

stCommand g_Command[] = {
  "u", &CmdDisAsm,
  "g", &CmdRun,
  "ret",&CmdExecTillRet,
  "r", &CmdRegister,
  "t", &CmdStep,
  "p",&CmdNext,
  "bp",&CmdBreakPoint,
  "bl", &CmdBreakPointList,
  "bc", &CmdBreakPointClear,
  "bm", &CmdBreakMem,
  "bml", &CmdBreakMemList,
  "bmc", &CmdBreakMemClear,
  "ba",&CmdBreakHard,
  "bal",&CmdBreakHardList,
  "bac", &CmdBreakHardClear,
	"dd",&CmdDisplayMemory,
	"ed", &CmdModifyMemory,
	"lm",&CmdListModules,

};


void Help() {
	printf("Help:\n");
	printf("-exec path\n");   //start debugging  
	printf("-pid process id\n");
	printf("-args command args\n");
}

//show error message
int ShowErrMsg(const char* lpFunName) {
	LPVOID lpMsgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //Default language
		(LPTSTR)&lpMsgBuf,
		0,
		NULL
	);

	LOGD("%s Error:%d Msg:%s\n",
		lpFunName,
		GetLastError(),
		(LPCTSTR)lpMsgBuf);
	LocalFree(lpMsgBuf);
	return 0;
}

// debug application 
int DebugApp(const char* lpApplicationName, char* lpCommand) {
	// Initialize a debugging session for the specified application by creating a process with the DEBUG_PROCESS flag
	STARTUPINFO  si = { 0 };
	si.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION pi = { 0 };

	if (!CreateProcess(lpApplicationName,
		lpCommand,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,
		NULL,
		NULL,
		&si,
		&pi)) {
		ShowErrMsg("CreateProcess\n");
		return -1;
	};
	LOGD("CreateProcess dwProcessId:%d dwThreadId:%d\n", pi.dwProcessId, pi.dwThreadId);

	// wait for debugging events
	DEBUG_EVENT DbgEvent;

	//Debugger loop
	while (TRUE) {
		if (!WaitForDebugEvent(&DbgEvent, INFINITE)) {
			ShowErrMsg("WaitForDebugEvent\n");
			return -1;
		};
		//set default status as "not handled"   
		DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

		//Handle different types of debugging events
		switch (DbgEvent.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:
			dwContinueStatus = EventExec(&DbgEvent);
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			dwContinueStatus = EventCreateThread(&DbgEvent);
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			dwContinueStatus = EventCreateProcess(&DbgEvent);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			dwContinueStatus = EventExitThread(&DbgEvent);
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			dwContinueStatus = EventExitProcess(&DbgEvent);
			return 0;
			break;
		case LOAD_DLL_DEBUG_EVENT:
			dwContinueStatus = EventLoadDll(&DbgEvent);
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			dwContinueStatus = EventUnloadDll(&DbgEvent);
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			dwContinueStatus = EventOutputString(&DbgEvent);
			break;
		case RIP_EVENT:
			dwContinueStatus = EventRip(&DbgEvent);
			break;
		}
		if (!ContinueDebugEvent(DbgEvent.dwProcessId, DbgEvent.dwThreadId, dwContinueStatus)) {
			ShowErrMsg("ContinueDebugEvent\n");
			return -1;
		}
	}
	return 0;
}
//Exception event
DWORD EventExec(DEBUG_EVENT* lpEvent) {
	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED; //only exception could be passed back to the app. Other events can't be received by the app.
	EXCEPTION_RECORD* lpExceptionRecord = &lpEvent->u.Exception.ExceptionRecord;

	LOGI("Execption Event ExceptionCode:%08x ExceptionAddress:%p NumberParameters:%d param1:%08x Param2:%08x\n",
		lpExceptionRecord->ExceptionCode,
		lpExceptionRecord->ExceptionAddress,
		lpExceptionRecord->NumberParameters,
		lpExceptionRecord->ExceptionInformation[0],
		lpExceptionRecord->ExceptionInformation[1]);

	switch (lpExceptionRecord->ExceptionCode) {
	case EXCEPTION_BREAKPOINT:
		dwContinueStatus = ExecBreakPoint(lpEvent);
		break;
		//	A trace trap or other single-instruction mechanism signaled that one instruction has been executed.
	case EXCEPTION_SINGLE_STEP:
		dwContinueStatus = ExecStep(lpEvent);
		break;
		//previlleged instruction
	//The thread tried to execute an instruction whose operation is not allowed in the current machine mode.
	case EXCEPTION_PRIV_INSTRUCTION:
		dwContinueStatus = ExecPriv(lpEvent);
		break;
		//Memory access
	case EXCEPTION_ACCESS_VIOLATION:
		dwContinueStatus = ExecAccess(lpEvent);
		break;
	default:
		break;
	}


	return dwContinueStatus;
}


//Create Process Event
DWORD EventCreateProcess(DEBUG_EVENT* lpEvent) {
	LOGI("CreateProcess Event hProcess:%p lpBaseOfImage:%p lpStartAddress:%p\n",
		lpEvent->u.CreateProcessInfo.hProcess,
		lpEvent->u.CreateProcessInfo.lpBaseOfImage,
		lpEvent->u.CreateProcessInfo.lpStartAddress);

	//Set entry point bp
	MySetBreakPoint(lpEvent->dwProcessId, 1, lpEvent->u.CreateProcessInfo.lpStartAddress);

	return DBG_CONTINUE;
}


//Exit Process Event
DWORD EventExitProcess(DEBUG_EVENT* lpEvent) {
	LOGI("ExitProcess Event dwExitCode:%d\n",
		lpEvent->u.ExitProcess.dwExitCode);
	exit(0);
	return DBG_CONTINUE;
}

//Create Thread Event
DWORD EventCreateThread(DEBUG_EVENT* lpEvent) {
	LOGI("CreateThread Event hThread:%p lpStartAddress:%p lpThreadLocalBase:%p\n",
		lpEvent->u.CreateThread.hThread,
		lpEvent->u.CreateThread.lpStartAddress, //A pointer to the starting address of the thread.
		lpEvent->u.CreateThread.lpThreadLocalBase); //TEB
	return DBG_CONTINUE;
}

//Exit Process Event
DWORD EventExitThread(DEBUG_EVENT* lpEvent) {
	LOGI("ExitThread Event\n");
	return DBG_CONTINUE;
}

int MyReadProcessMemory(DWORD dwProcessId, LPCVOID lpBase, LPVOID lpBuffer,
	SIZE_T nSize) {
	SIZE_T nNumberOfBytesRead;
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, dwProcessId);
	if (hProcess == NULL) {
		ShowErrMsg("OpenProcess");
		return -1;
	}

	if (!ReadProcessMemory(hProcess,
		lpBase,
		lpBuffer,
		nSize,
		&nNumberOfBytesRead)) {
		ShowErrMsg("ReadProcessMemory");
		nNumberOfBytesRead = -1;
	}

	CloseHandle(hProcess);
	return nNumberOfBytesRead;
}

int MyWriteProcessMemory(DWORD dwProcessId, LPVOID lpBase, LPVOID lpBuffer,
	SIZE_T nSize) {
	SIZE_T nNumberOfBytesRead;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL) {
		ShowErrMsg("OpenProcess");
		return -1;
	}

	if (!WriteProcessMemory(hProcess,
		lpBase,
		lpBuffer,
		nSize,
		&nNumberOfBytesRead)) {
		ShowErrMsg("WriteProcessMemory");
		nNumberOfBytesRead = -1;
	}

	CloseHandle(hProcess);
	return nNumberOfBytesRead;
}



DWORD GetOldProtect(DWORD lpAddress)
{
	for (const auto& page : g_pages) {
		if ((lpAddress & 0xfffff000) == (DWORD)page.lpBaseAddress) {
			return page.oldProtect;
		}
	}
	return 0;
}

int CmdDisAsm(DEBUG_EVENT* lpEvent, const char* lpCmd) {
	char szCmd[16];
	LPVOID lpAddress = NULL;
	ULONG nLine = 0;
	sscanf_s(lpCmd, "%s %p %d", szCmd, sizeof(szCmd),
		&lpAddress, &nLine);

	LOGI("DisAsm szCmd:%s lpAddress:%p nLine:%d\n",
		szCmd, lpAddress, nLine);

	if (lpAddress == NULL && g_lpDisAddr == NULL) {
		// if no address is provided, show the assembly code of eip
		CONTEXT Context;
		MyReadRegisters(lpEvent->dwThreadId, &Context);
		lpAddress = (LPVOID)Context.Eip;
	}
	if (nLine == 0)
		nLine = 7;

	MyDisAsm(lpEvent->dwProcessId, lpAddress, nLine);

	return 0;
}

int CmdRun(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	char szCmd[16];
	LPVOID lpAddress = NULL;
	ULONG nLine = 0;
	sscanf_s(lpCmd, "%s %p", szCmd, sizeof(szCmd), &lpAddress);

	if (lpAddress != NULL)
		MySetBreakPoint(lpEvent->dwProcessId, 1, lpAddress);
	return -1;
}

int CmdExecTillRet(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	CONTEXT Context;
	if (MyReadRegisters(lpEvent->dwThreadId, &Context) < 0) {
		return -1;
	}
	// get the return address. The return address is at ebp + 4
	DWORD dwRetAddr;
	if (MyReadProcessMemory(lpEvent->dwProcessId, (LPVOID)(Context.Ebp + 4), &dwRetAddr, sizeof(DWORD)) < 0) {
		return -1;
	}


	// set a temporary bp at the return address
	MySetBreakPoint(lpEvent->dwProcessId, 1, (LPVOID)dwRetAddr);

	// continue to run until meet the temporary bp
	return  -1;
}

int CmdRegister(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	char szCmd[32];
	char szReg[16];
	memset(szCmd, 0, sizeof(szCmd));
	memset(szReg, 0, sizeof(szReg));
	sscanf_s(lpCmd, "%s %s", szCmd, sizeof(szCmd), szReg, sizeof(szReg));
	szReg[sizeof(szReg) - 1] = '\0';
	// r : if no register is specified, show all registers
	if (strlen(szReg) == 0) {
		MyShowReg(lpEvent->dwThreadId);
	}
	// r reg=value ; modify the value of specified register
	else if (strchr(szReg, '=') != NULL) {
		MyModifyReg(lpEvent->dwThreadId, szReg);
	}
	else {
		// r reg : show a specific register
		MyShowSpecReg(lpEvent->dwThreadId, szReg);
	}
	return 0;
}

int CmdStep(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	MySetStep(lpEvent->dwThreadId);
	g_IsStep = TRUE;
	return -1;
}

int CmdNext(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	//get the length of EIP instruction
	CONTEXT Context;
	MyReadRegisters(lpEvent->dwThreadId, &Context);

	BYTE ByteCode[10];
	UINT nCodeSize = 0;
	char szAsm[260];

	if (MyReadProcessMemory(lpEvent->dwProcessId,
		(LPVOID)Context.Eip,
		ByteCode, sizeof(ByteCode)) < 0) {
		return -1;
	}

	Decode2Asm(ByteCode, szAsm, &nCodeSize, Context.Eip);
	// if the instruction is a call, go to the next instruction
	// otherwise, set single-step exection. p = t
	if (strncmp(szAsm, "call", 4) == 0)
	{
		MySetBreakPoint(lpEvent->dwProcessId, 1, (LPVOID)(Context.Eip + nCodeSize));
	}
	else {
		MySetStep(lpEvent->dwThreadId);
		g_IsStep = TRUE;
	}

	return -1;
}


int CmdBreakPoint(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	char szCmd[16];
	LPVOID lpAddress = NULL;
	UINT nType = 2;     //  1 means one-time, 2 means permenant. set permenant as default
	sscanf_s(lpCmd, "%s %p %u", szCmd, sizeof(szCmd),
		&lpAddress, &nType);
	if (lpAddress == NULL) {
		printf("lpAddress == NULL! Please speficy an address for breakpoint.\n");
		return 0;
	}

	MySetBreakPoint(lpEvent->dwProcessId, nType, lpAddress);
	return 0;
}

int CmdBreakPointList(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	printf("Software Breakpoint List:\n");
	printf("Index\tAddress\t\tEnabled\tType\n");
	int index = 0;
	for (const auto& bp : g_softBp) {
		printf("%d\t%p\t%s\t%s\n",
			index,
			bp.lpAddress,
			bp.IsEnable ? "Yes" : "No",
			bp.oneTime ? "OneTime" : "Permanent");
		index++;
	}
	return 0;
}

int CmdBreakPointClear(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	int index;
	if (sscanf_s(lpCmd, "bc %d", &index) != 1 || index < 0 || index >= g_softBp.size()) {
		printf("Invalid break point index\n");
		return 0;
	}

	auto it = g_softBp.begin();
	std::advance(it, index);
	if (it->IsEnable) {
		MyWriteProcessMemory(lpEvent->dwProcessId, it->lpAddress, &it->originalByte, sizeof(it->originalByte));
	}
	//// If deleting the breakpoint currently being processed, yset g_IsBpStep to false
	//if (it->lpAddress == g_lpBpAddress) {
	//	g_IsBpStep = false;
	//}

	g_softBp.erase(it);
	return 0;
}

int CmdBreakMem(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	char szCmd[16];
	char chType = -1;
	UINT nSize = 0;
	PVOID lpAddress = NULL;

	sscanf_s(lpCmd, "%s %c %d %p", szCmd, sizeof(szCmd),
		&chType, sizeof(char), &nSize, &lpAddress);
	if (chType == -1 || nSize == 0 || lpAddress == NULL) {
		printf("Invalid Param\n");
		return 0;
	}
	// check if the breakpoint already exists in the breakpoint list
	// if not, set the bp
	if (IsMemBpExists(lpAddress, chType, nSize)) {
		printf("break point already exists.");
		return 0;
	}
	MySetBreakMem(lpEvent->dwProcessId, lpAddress, chType, nSize);
	return 0;
}

int CmdBreakMemList(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	int i = 0;
	printf("%-10s%-10s%-10s%-10s\n", "Index", "Address", "Type", "Length");
	for (const auto& bmp : g_memBps) {
		printf("%-10d%-10p%-10c%-10d\n",
			i, bmp.lpAddress, bmp.chType, bmp.nLen);
		i++;
	}
	return 0;
}

int CmdBreakMemClear(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	int index;
	if (sscanf_s(lpCmd, "bmc %d", &index) != 1) {
		printf("Invalid memory breakpoint index\n");
		return 0;
	}
	// delete bp from g_memBps and  obtain the Id of the deleted bp
	int nId = MyRemoveBreakMem(index);
	if (nId == -1) {
		return 0;
	}
	// remove the bp from bp-page mapping list
	std::list<LPVOID> deletedPages = MyRemoveBpPageMapping(nId);
	//iterate bp-page mapping list to check if the pages are used by other bp
		// if not, delete from g_pages and change back the protection options
	// if yes, do not modify g_pages;
	for (const auto& page : deletedPages) {
		if (!IsPageUsedByOtherBps(page)) {
			//delete page from g_pages
			DWORD dwProtect = MyRemovePages(page);
			DWORD dwOldProtect;
			if (MyVirtualProtectEx(lpEvent->dwProcessId,
				page,
				0x1000,
				dwProtect,
				&dwOldProtect) == -1) {
				printf("Failed to restore page protection\n");
				continue;
			}



		}

	}

	return 0;
}

//handle hard breakpoint command
int CmdBreakHard(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	char szCmd[16];
	int nType = -1;
	int nLen = -1;
	PVOID lpAddress = NULL;

	sscanf_s(lpCmd, "%s %p %d %d", szCmd, sizeof(szCmd),
		&lpAddress, &nType, &nLen);
	if (nType == -1 || nLen == -1 || lpAddress == NULL) {
		printf("Invalid Param\n");
		return 0;
	}

	return MySetBreakHard(lpEvent->dwThreadId, lpAddress, nType, nLen);
}

// list hardware bp
int CmdBreakHardList(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	printf("%-10s%-10s%-10s%-10s%-10s\n", "Index", "Enable", "Address", "Type", "Len");
	for (int i = 0; i < 4; i++) {
		printf("%-10d%-10d%-10p%-10d%-10d\n",
			i, g_HardBp[i].IsEnable, g_HardBp[i].lpAddress,
			g_HardBp[i].nType, g_HardBp[i].nLen);
	}
	return 0;
}

int CmdBreakHardClear(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	int index;
	if (sscanf_s(lpCmd, "bac %d", &index) != 1 || index < 0 || index >= 3) {
		printf("Invalid hardware break point index\n");
		return 0;
	}
	for (int i = 0; i < 4; i++) {
		if (i == index) {
			MyRemoveBreakHard(lpEvent->dwThreadId, index);
		}
	}
	return 0;
}

int CmdDisplayMemory(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	char szCmd[8] = { 0 };
	char szAddress[16] = { 0 };
	SIZE_T nLen = 0;
	LPVOID lpBaseAddress = NULL;
	BYTE* pBuffer = NULL;
	sscanf_s(lpCmd, "%s %s %zu", szCmd, sizeof(szCmd), szAddress, sizeof(szAddress), &nLen);
	// if szAddress == NULL and  g_lpShowMemAddr == NULL, use eip as the base address to display memory

	if (szAddress[0] == '\0' && g_lpShowMemAddr == NULL) {
		CONTEXT Context;
		MyReadRegisters(lpEvent->dwThreadId, &Context);
		lpBaseAddress = (LPVOID)(DWORD_PTR)Context.Eip;
	}
	// if no input address, display the last memory address that was displayed 
	else if (szAddress[0] == '\0' && g_lpShowMemAddr != NULL)
	{
		lpBaseAddress = g_lpShowMemAddr;
	}
	else if (szAddress[0] != '\0') {
		lpBaseAddress = (LPVOID)strtoul(szAddress, NULL, 16);
	}
	else {
		return -1;
	}
	SIZE_T bytesToRead = (nLen == 0) ? 128 : nLen * 4; // default to 128 if length is 0
	pBuffer = (BYTE*)malloc(bytesToRead);
	if (pBuffer == NULL) {
		ShowErrMsg("malloc");
		return -1;
	}
	if (!MyReadProcessMemory(lpEvent->dwProcessId, lpBaseAddress, pBuffer, bytesToRead)) {
		ShowErrMsg("MyReadProcessMemory");
		free(pBuffer);
		return -1;
	}
	//print memory
	DWORD* pDword = (DWORD*)pBuffer;
	SIZE_T dwordsToDisplay = bytesToRead / 4;
	for (SIZE_T i = 0; i < dwordsToDisplay; i += 4) {
		printf("%p  ", (LPVOID)((DWORD_PTR)lpBaseAddress + i * 4));
		for (SIZE_T j = 0; j < 4 && (i + j) < dwordsToDisplay; j++) {
			printf("%08x ", pDword[i + j]);
		}
		printf("\n");
	}

	g_lpShowMemAddr = (LPVOID)((DWORD_PTR)lpBaseAddress + bytesToRead);
	free(pBuffer);
	return 0;


}

int CmdModifyMemory(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	char szCmd[8] = { 0 };
	LPVOID lpAddress;
	DWORD dwValue;
	sscanf_s(lpCmd, "%s %p %x", szCmd, sizeof(szCmd), &lpAddress, &dwValue);
	MyWriteProcessMemory(lpEvent->dwProcessId, lpAddress, &dwValue, sizeof(DWORD));
	return 0;
}

int CmdListModules(DEBUG_EVENT* lpEvent, const char* lpCmd)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	//  Take a snapshot of all modules in the specified process. 
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, lpEvent->dwProcessId);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		ShowErrMsg("CreateToolhelp32Snapshot (of modules)");
		return -1;
	}

	//  Set the size of the structure before using it. 
	me32.dwSize = sizeof(MODULEENTRY32);

	//  Retrieve information about the first module, 
	//  and exit if unsuccessful 
	if (!Module32First(hModuleSnap, &me32))
	{
		ShowErrMsg("Module32First");  // Show cause of failure 
		CloseHandle(hModuleSnap);     // Must clean up the snapshot object! 
		return -1;
	}

	//  Now walk the module list of the process, 
	//  and display information about each module 
	do
	{
		printf(TEXT("\n\n     MODULE NAME:     %s"), me32.szModule);
		printf(TEXT("\n     executable     = %s"), me32.szExePath);
		printf(TEXT("\n     process ID     = 0x%08X"), me32.th32ProcessID);
		printf(TEXT("\n     ref count (g)  =     0x%04X"), me32.GlblcntUsage);
		printf(TEXT("\n     ref count (p)  =     0x%04X"), me32.ProccntUsage);
		printf(TEXT("\n     base address   = 0x%08X"), (DWORD)me32.modBaseAddr);
		printf(TEXT("\n     base size      = %d"), me32.modBaseSize);

	} while (Module32Next(hModuleSnap, &me32));

	printf(TEXT("\n"));

	//  Do not forget to clean up the snapshot object. 
	CloseHandle(hModuleSnap);
	return 0;

}

DWORD EventLoadDll(DEBUG_EVENT* lpEvent)
{
	wchar_t szImageName[MAX_PATH];
	LPVOID lpImageNamePtr = NULL;
	LOGI("LoadDll Event lpBaseOfDll:%p\n", lpEvent->u.LoadDll.lpBaseOfDll);
	return DBG_CONTINUE;

	//read the pointer to the image name
	if (MyReadProcessMemory(lpEvent->dwProcessId, lpEvent->u.LoadDll.lpImageName,
		lpImageNamePtr, sizeof(lpImageNamePtr)) < 0) {
		printf("\n");
		return DBG_CONTINUE;
	}

	//Read the actual image name
	if (lpImageNamePtr && MyReadProcessMemory(lpEvent->dwProcessId, lpImageNamePtr,
		szImageName, sizeof(szImageName)) < 0) {

		LOGI("Failed to read image name. fUnicode:%d lpImageName:%p\n",
			lpEvent->u.LoadDll.fUnicode,
			lpEvent->u.LoadDll.lpImageName);
	}
	else {
		if (lpEvent->u.LoadDll.fUnicode) {
			LOGI("fUnicode%d lpImageName:%ws\n",
				lpEvent->u.LoadDll.fUnicode,
				szImageName);
		}
		else {
			LOGI("fUnicode%d lpImageName:%s\n",
				lpEvent->u.LoadDll.fUnicode,
				(char*)szImageName);
		}
	}

	return DBG_CONTINUE;
}



DWORD EventUnloadDll(DEBUG_EVENT* lpEvent) {
	LOGI("Unload Event\n");
	return DBG_CONTINUE;
}

DWORD EventOutputString(DEBUG_EVENT* lpEvent) {
	LOGI("Debugput Event\n");
	return DBG_CONTINUE;
}

DWORD EventRip(DEBUG_EVENT* lpEvent) {
	LOGI("Rip Event\n");
	return DBG_CONTINUE;
}

//handle EXCEPTION_BREAKPOINT 
// the function below uses previlleged funtion to set bp
//DWORD ExecBreakPoint(DEBUG_EVENT* lpEvent) {
//	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
//	EXCEPTION_RECORD* lpExceptionRecord = &lpEvent->u.Exception.ExceptionRecord;
//
//	// handle system break point
//	if (g_IsSystemBreakPoint) {
//		g_IsSystemBreakPoint = false;
//
//		MyShowReg(lpEvent->dwThreadId);
//
//		CONTEXT Context;
//		MyReadRegisters(lpEvent->dwThreadId, &Context);
//		MyDisAsm(lpEvent->dwProcessId, (LPVOID)Context.Eip, 1);
//
//		return DBG_CONTINUE;
//	}
//
//	return dwContinueStatus;
//}

//use int 3 to set bp
DWORD ExecBreakPoint(DEBUG_EVENT* lpEvent) {
	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
	EXCEPTION_RECORD* lpExceptionRecord = &lpEvent->u.Exception.ExceptionRecord;

	// check if the exception is caused by system bp
	if (g_IsSystemBreakPoint) {
		g_IsSystemBreakPoint = false;
		MyShowReg(lpEvent->dwThreadId);
		CONTEXT Context;
		MyReadRegisters(lpEvent->dwThreadId, &Context);
		MyDisAsm(lpEvent->dwProcessId, (LPVOID)Context.Eip, 1);
		if (GetCommand(lpEvent) < 0)
			exit(0);
		return DBG_CONTINUE;
	}

	// check if exception is caused by software bp
	//iterate software bp list
	for (auto& bp : g_softBp) {
		if (lpExceptionRecord->ExceptionAddress == bp.lpAddress && bp.IsEnable) {
			// restore the original code
			MyWriteProcessMemory(lpEvent->dwProcessId,
				lpExceptionRecord->ExceptionAddress,
				&bp.originalByte, sizeof(bp.originalByte));

			// change EIP to eip -1 since int 3 is one byte
			CONTEXT Context;
			MyReadRegisters(lpEvent->dwThreadId, &Context);
			Context.Eip -= 1;
			MyWriteRegisters(lpEvent->dwThreadId, &Context);

			// if permenant bp, set single step to re-establish the bp
			if (!bp.oneTime) {
				MySetStep(lpEvent->dwThreadId);
				g_IsBpStep = true;
				g_lpBpAddress = bp.lpAddress;
			}
			else {
				// if one-time bp, disable it
				bp.IsEnable = false;
			}

			MyShowReg(lpEvent->dwThreadId);
			MyDisAsm(lpEvent->dwProcessId, lpExceptionRecord->ExceptionAddress, 1);

			if (GetCommand(lpEvent) < 0)
				exit(0);

			return DBG_CONTINUE;
		}
	}

	return dwContinueStatus;
}


//handle EXCEPTION_SINGLE_STEP
DWORD ExecStep(DEBUG_EVENT* lpEvent) {
	EXCEPTION_RECORD* lpExceptionRecord = &lpEvent->u.Exception.ExceptionRecord;
	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

	//check hardware bp
	CONTEXT Context;
	if (MyReadRegisters(lpEvent->dwThreadId, &Context) == 0) {
		DR6 dr6;
		dr6.val = Context.Dr6;
		DR7 dr7;
		dr7.val = Context.Dr7;
		// for execution breakpoint, have to reset the bp

		if (dr6.val & 0xf) {
			if (dr6.B0 && g_HardBp[0].nType == 0)
				dr7.L0 = 0;
			if (dr6.B1 && g_HardBp[1].nType == 0) {
				dr7.L1 = 0;
			}
			if (dr6.B2 && g_HardBp[2].nType == 0) {
				dr7.L2 = 0;
			}
			if (dr6.B3 && g_HardBp[3].nType == 0) {
				dr7.L3 = 0;
			}
			Context.Dr7 = dr7.val;
			MyWriteRegisters(lpEvent->dwThreadId, &Context);


			//MySetStep(lpEvent->dwThreadId);
			//g_IsHardStep = true;

			MyShowReg(lpEvent->dwThreadId);
			MyDisAsm(lpEvent->dwProcessId, lpExceptionRecord->ExceptionAddress, 1);
			// reset hard bp
			MyResetBreakHard(lpEvent->dwThreadId, g_HardBp);
			if (GetCommand(lpEvent) < 0)
				exit(0);
			dwContinueStatus = DBG_CONTINUE;
		}
	}


	// memory bp
	if (g_IsMemStep) {
		g_IsMemStep = FALSE;

		//change the memory protection constant
		MyVirtualProtectEx(lpEvent->dwProcessId,
			g_lpMemAddress, g_nMemSize,
			PAGE_NOACCESS, &g_nMemOldProto);
		dwContinueStatus = DBG_CONTINUE;
	}

	//software bp
	if (g_IsBpStep) {
		g_IsBpStep = false;
		for (auto& bp : g_softBp) {
			if (bp.lpAddress == g_lpBpAddress && bp.IsEnable && !bp.oneTime) {
				MySetBreakPoint(lpEvent->dwProcessId, 2, g_lpBpAddress);
				break;
			}
		}

		dwContinueStatus = DBG_CONTINUE;
	}

	//t single-step execution
	if (g_IsStep) {
		g_IsStep = false;
		MyShowReg(lpEvent->dwThreadId);
		MyDisAsm(lpEvent->dwProcessId, lpExceptionRecord->ExceptionAddress, 1);

		if (GetCommand(lpEvent) < 0)
			exit(0);

		dwContinueStatus = DBG_CONTINUE;
	}

	return dwContinueStatus;
}

//Break point handling 
//if previlleged instruction is used, when a breakpoint is hit, it triggers an EXCEPTION_PRIV_INSTRUCTION exception
//DWORD ExecPriv(DEBUG_EVENT* lpEvent)
//{
//	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
//	EXCEPTION_RECORD* lpExceptionRecord = &lpEvent->u.Exception.ExceptionRecord;
//
//
//	// Check if the breakpoint is at entry
//	if (lpExceptionRecord->ExceptionAddress == g_lpEntryAddress) {
//		//restore the original instruction
//		MyWriteProcessMemory(lpEvent->dwProcessId,
//			lpExceptionRecord->ExceptionAddress,
//			&g_EntryCode, sizeof(g_EntryCode));
//
//		MyShowReg(lpEvent->dwThreadId);
//		MyDisAsm(lpEvent->dwProcessId, lpExceptionRecord->ExceptionAddress, 1);
//
//		if (GetCommand(lpEvent) < 0)
//			exit(0);
//
//		return DBG_CONTINUE;
//	}
//	//check if the exception is a breakpoint exception set by the debugger
//	else if (lpExceptionRecord->ExceptionAddress == g_lpBpAddress) {
//		//restore the original code
//		MyWriteProcessMemory(lpEvent->dwProcessId,
//			lpExceptionRecord->ExceptionAddress,
//			&g_OldCode, sizeof(g_OldCode));
//
//		//EIP - 1
//		//CONTEXT Context;
//		//MyReadRegisters(lpEvent->dwThreadId, &Context);
//		//Context.Eip -= 1;
//		//MyWriteRegisters(lpEvent->dwThreadId, &Context);
//
//		MyShowReg(lpEvent->dwThreadId);
//		MyDisAsm(lpEvent->dwProcessId, lpExceptionRecord->ExceptionAddress, 1);
//
//		//For software breakpoints, single-step execution is set to re-establish the breakpoint
//		MySetStep(lpEvent->dwThreadId);
//		g_IsBpStep = true;
//
//		if (GetCommand(lpEvent) < 0)
//			exit(0);
//
//		return DBG_CONTINUE;
//	}
//
//	return dwContinueStatus;
//}
DWORD ExecPriv(DEBUG_EVENT* lpEvent)
{
	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
	EXCEPTION_RECORD* lpExceptionRecord = &lpEvent->u.Exception.ExceptionRecord;


	return dwContinueStatus;
}

DWORD ExecAccess(DEBUG_EVENT* lpEvent)
{
	DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
	EXCEPTION_RECORD* lpExceptionRecord = &lpEvent->u.Exception.ExceptionRecord;
	ULONG nType = lpExceptionRecord->ExceptionInformation[0];  //0: read 1: write
	ULONG nAddress = lpExceptionRecord->ExceptionInformation[1];
	DWORD dwOld = 0;

	//check if the exception is caused by debugger
	//1. check if the page exists in the bp-page mapping list. 
	// if yes, return the id of the break point. 
	// if not, the exception is not caused by the memory bp set by the debugger. 
	std::list<UINT> lstResult = IsPageInBpPageMapping((DWORD)nAddress);
	if (!lstResult.empty()) {
		//2. check the g_memBps list to obtain length and type.
		// if the address falls within the range of the memory bp and the protection constant is the same
		// the exception is caused by the debugger
		DWORD dwProtect = GetOldProtect(nAddress);
		for (const auto& id : lstResult) {
			for (const auto& mbp : g_memBps) {
				if (id == mbp.nId) {
					// get the saved old protect option from g_pages
			
					if (nAddress >= (UINT)mbp.lpAddress && nAddress <= (UINT)mbp.lpAddress + mbp.nLen) {
						if ((mbp.chType == 'w' && nType == 1) ||  // Write access
							(mbp.chType == 'a' && (nType == 0 || nType == 1)))  // Any access
						{
							// change back the memory protection 
							MyVirtualProtectEx(lpEvent->dwProcessId,
								mbp.lpAddress, mbp.nLen, dwProtect, &dwOld);
							//Show registers and disassembly
							MyShowReg(lpEvent->dwThreadId);
							MyDisAsm(lpEvent->dwProcessId, lpExceptionRecord->ExceptionAddress, 1);

							// set a single-step
							g_nMemSize = mbp.nLen;
							g_lpMemAddress = mbp.lpAddress;
							MySetStep(lpEvent->dwThreadId);
							g_IsMemStep = true;

							//Get user input
							if (GetCommand(lpEvent) < 0)
								exit(0);
							return DBG_CONTINUE;
						}
					}

				}
				// if not exactly the same as the bp set by the debugger
				// change back the memory protection options, and set single step
				MyVirtualProtectEx(lpEvent->dwProcessId,
					mbp.lpAddress, mbp.nLen, dwProtect, &dwOld);
				//single-step execution
				g_nMemSize = mbp.nLen;
				g_lpMemAddress = mbp.lpAddress;
				MySetStep(lpEvent->dwThreadId);
				g_IsMemStep = true;

				return DBG_CONTINUE;
			}
		}



	}
	if (GetCommand(lpEvent) < 0)
		exit(0);

	return dwContinueStatus;
}

/*
	//Check if the address of the exception is in the same page as the memory breakpoint set by the debugger.
	if ((nAddress & 0xfffff000) == ((UINT)g_lpMemAddress & 0xfffff000)) {
		//check if the address falls within the range of the memory bp
		if ((nAddress >= (UINT)g_lpMemAddress) &&
			(nAddress <= (UINT)g_lpMemAddress + g_nMemSize)) {
			// check if the memory protection constant is the same as the memory bp's
			if (nType == g_chMemType) {
				//it is the memory bp. change back the memory protection constant.
				MyVirtualProtectEx(lpEvent->dwProcessId,
					g_lpMemAddress, g_nMemSize,
					g_nMemOldProto, &dwOld);

				MyShowReg(lpEvent->dwThreadId);
				MyDisAsm(lpEvent->dwProcessId, lpExceptionRecord->ExceptionAddress, 1);

				//set a single-step
				MySetStep(lpEvent->dwThreadId);
				g_IsMemStep = true;

				if (GetCommand(lpEvent) < 0)
					exit(0);
				return DBG_CONTINUE;
			}
		}

		//change back the memory protection constant
		MyVirtualProtectEx(lpEvent->dwProcessId,
			g_lpMemAddress, g_nMemSize,
			g_nMemOldProto, &dwOld);

		//single-step execution
		MySetStep(lpEvent->dwThreadId);
		g_IsMemStep = true;

		return DBG_CONTINUE;
	}

	if (GetCommand(lpEvent) < 0)
		exit(0);

	return dwContinueStatus;
}
*/



int GetCommand(DEBUG_EVENT* lpEvent) {
	//wait for command u  p  t  bp
	char szInput[260];
	char szCmd[16];
	int nResult = 0;

	//u addr len
	while (nResult == 0) {
		fgets(szInput, sizeof(szInput), stdin);
		int nBytes = sscanf_s(szInput, "%s", szCmd, sizeof(szCmd));
		if (nBytes > 0) {


			//Convert uppercase to lowercase
			_strlwr_s(szCmd, sizeof(szCmd));


			//process command
			int i = 0;
			for (; i < sizeof(g_Command) / sizeof(g_Command[0]); i++) {
				if (strcmp(szCmd, g_Command[i].cmd) == 0) {
					nResult = g_Command[i].pfn(lpEvent, szInput);
					if (nResult == -1)
						return 0;
					break;
				}
			}


			if (i == sizeof(g_Command) / sizeof(g_Command[0])) {
				printf("Invalid Command\n");
			}
		}
	}

	return nResult;
}
//Read and disassemble machine code from a specified address in specified process's memory. 
//read a block of memory, decodes it into assembly instructions, 
//and prints both the raw bytecode and corresponding assembly instructions for each line specified by nLine
int MyDisAsm(DWORD dwProcessId, LPVOID lpAddress, UINT nLine) {
	BYTE ByteCode[0x1000];
	char szAsm[260];
	UINT nCodeSize = 0;
	BYTE* pCode = ByteCode;
	//update g_lpDisAddress
	if (lpAddress != NULL) {
		g_lpDisAddr = lpAddress;
	}

	// show assembly
	if (MyReadProcessMemory(dwProcessId,
		g_lpDisAddr,
		ByteCode, sizeof(ByteCode)) < 0) {
		return -1;
	}
	//call Decode2Asm to decode the machine code at pCode into assembly language
	for (UINT i = 0; i < nLine; i++) {
		Decode2Asm(pCode, szAsm, &nCodeSize, (UINT)g_lpDisAddr);
		printf("%p ", g_lpDisAddr);
		for (UINT i = 0; i < 8; i++) {
			if (i < nCodeSize)
				printf("%02X ", pCode[i]);
			else
				printf("   ");
		}
		printf("%s\n", szAsm);
		pCode += nCodeSize;
		g_lpDisAddr = (BYTE*)g_lpDisAddr + nCodeSize;
	}
	return 0;
}

int MyShowReg(DWORD dwThreadId)
{
	CONTEXT Context;
	MyReadRegisters(dwThreadId, &Context);
	printf("eax:%08x ecx:%08x edx:%08x ebx:%08x\n"
		"esp:%08x ebp:%08x esi:%08x edi:%08x\n"
		"eip:%08x eflag:%08x\n"
		"dr0:%08x dr1:%08x dr2:%08x dr3:%08x \n"
		"dr6:%08x\n",
		Context.Eax,
		Context.Ecx,
		Context.Edx,
		Context.Ebx,
		Context.Esp,
		Context.Ebp,
		Context.Esi,
		Context.Edi,
		Context.Eip,
		Context.EFlags,
		Context.Dr0,
		Context.Dr1,
		Context.Dr2,
		Context.Dr3,
		Context.Dr6);
	return 0;
}

int MyModifyReg(DWORD dwThreadId, char* szReg)
{
	CONTEXT Context;
	char szRegName[8];
	char szValue[16];
	char* pos = strchr(szReg, '=');
	// get register name and value
	strncpy_s(szRegName, sizeof(szRegName), szReg, pos - szReg);
	strcpy_s(szValue, sizeof(szValue), pos + 1);
	MyReadRegisters(dwThreadId, &Context);
	_strlwr_s(szReg, strlen(szReg) + 1);
	DWORD value;
	sscanf_s(szValue, "%x", &value);
	if (strcmp(szRegName, "eax") == 0) {
		Context.Eax = value;
	}
	else if (strcmp(szRegName, "ecx") == 0) {
		Context.Ecx = value;
	}
	else if (strcmp(szRegName, "edx") == 0) {
		Context.Edx = value;
	}
	else if (strcmp(szRegName, "ebx") == 0) {
		Context.Ebx = value;
	}
	else if (strcmp(szRegName, "esp") == 0) {
		Context.Esp = value;
	}
	else if (strcmp(szRegName, "ebp") == 0) {
		Context.Ebp = value;
	}
	else if (strcmp(szRegName, "esi") == 0) {
		Context.Esi = value;
	}
	else if (strcmp(szRegName, "edi") == 0) {
		Context.Edi = value;
	}
	else if (strcmp(szRegName, "eip") == 0) {
		Context.Eip = value;
	}
	else if (strcmp(szRegName, "eflags") == 0) {
		Context.EFlags = value;
	}
	else {
		printf("please enter a valid register\n");
		return 0;
	}
	MyWriteRegisters(dwThreadId, &Context);

	return 0;
}

int MyShowSpecReg(DWORD dwThreadId, char* szReg)
{
	CONTEXT Context;
	MyReadRegisters(dwThreadId, &Context);
	_strlwr_s(szReg, strlen(szReg) + 1);
	if (strcmp(szReg, "eax") == 0) {
		printf("%s: %08x\n", szReg, Context.Eax);
	}
	else if (strcmp(szReg, "ecx") == 0) {
		printf("%s: %08x\n", szReg, Context.Ecx);
	}
	else if (strcmp(szReg, "edx") == 0) {
		printf("%s: %08x\n", szReg, Context.Edx);
	}
	else if (strcmp(szReg, "ebx") == 0) {
		printf("%s: %08x\n", szReg, Context.Ebx);
	}
	else if (strcmp(szReg, "esp") == 0) {
		printf("%s: %08x\n", szReg, Context.Esp);
	}
	else if (strcmp(szReg, "ebp") == 0) {
		printf("%s: %08x\n", szReg, Context.Ebp);
	}
	else if (strcmp(szReg, "esi") == 0) {
		printf("%s: %08x\n", szReg, Context.Esi);
	}
	else if (strcmp(szReg, "edi") == 0) {
		printf("%s: %08x\n", szReg, Context.Edi);
	}
	else if (strcmp(szReg, "eip") == 0) {
		printf("%s: %08x\n", szReg, Context.Eip);
	}
	else if (strcmp(szReg, "eflags") == 0) {
		printf("%s: %08x\n", szReg, Context.EFlags);
	}
	else {
		printf("please enter a valid register\n");
	}
	return 0;
}

//Read Registers for given Thread
int MyReadRegisters(DWORD dwThreadId, CONTEXT* pContext) {
	int nResult = -1;

	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, dwThreadId);
	if (hThread == NULL) {
		ShowErrMsg("OpenThread");
		return nResult;
	}

	pContext->ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(hThread, pContext)) {
		ShowErrMsg("GetThreadContext");
	}
	else {
		nResult = 0;
	}

	CloseHandle(hThread);
	return nResult;
}

//Write Registers for given thread
int MyWriteRegisters(DWORD dwThreadId, CONTEXT* pContext) {
	int nResult = -1;

	HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, dwThreadId);
	if (hThread == NULL) {
		ShowErrMsg("OpenThread");
		return nResult;
	}

	pContext->ContextFlags = CONTEXT_ALL;
	if (!SetThreadContext(hThread, pContext)) {
		ShowErrMsg("SetThreadContext");
	}
	else {
		nResult = 0;
	}

	CloseHandle(hThread);
	return nResult;
}

//Implement single-step execution
int MySetStep(DWORD dwThreadId)
{
	//set TF=1
	CONTEXT Context;
	if (MyReadRegisters(dwThreadId, &Context) == 0) {
		Context.EFlags |= EFLAGS_TF;
		MyWriteRegisters(dwThreadId, &Context);
	}
	return 0;
}

//Use Previlleged instruction to  Implement the Software breakpoint
/*int MySetBreakPoint(DWORD dwProcessId, LPVOID lpAddress)
{
	// Use the CLI instruction to set the breakpoint. CLI is a previliged code that can only be executed in Kernel mode
//use CLI instead of int 3 for anti-debugging
	char Code = 0xfa;
	g_lpBpAddress = lpAddress;

	// save the old instruction
	MyReadProcessMemory(dwProcessId, lpAddress, &g_OldCode,
		sizeof(g_OldCode));

	// Uses the CLI instruction (0xFA) to replace the original instruction at the target address
	MyWriteProcessMemory(dwProcessId, lpAddress, &Code,
		sizeof(Code));

	return 0;
}*/

// use int 3 to implement software breakpoint
int MySetBreakPoint(DWORD dwProcessId, UINT nType, LPVOID lpAddress)
{


	unsigned char Code = 0xcc;
	//g_lpBpAddress = lpAddress;
	BYTE oldCode;
	//save old codes
	MyReadProcessMemory(dwProcessId, lpAddress, &oldCode,
		sizeof(oldCode));

	//modify code to int 3
	MyWriteProcessMemory(dwProcessId, lpAddress, &Code,
		sizeof(Code));
	//check if the break point exists in the same address already
	bool exists = false;
	for (const auto& bp : g_softBp) {
		if (bp.lpAddress == lpAddress) {
			exists = true;
			break;
		}
	}
	if (!exists) {
		g_softBp.push_back({ lpAddress, oldCode, true, nType == 1 });
	}

	//g_nBpType = nType;
	return 0;
}

//set hardware breakpoint
int MySetBreakHard(DWORD dwThreadId, LPVOID lpAddress, UINT nType, UINT nLen)
{
	LOGI("MySetBreakHard lpAddress=%p nType:%d nLen:%d\n",
		lpAddress, nType, nLen);


	for (int i = 0; i < 4; i++) {
		// if the hardware bp is not set, set the  bp
		if (!g_HardBp[i].IsEnable) {
			CONTEXT Context;
			if (MyReadRegisters(dwThreadId, &Context) < 0)
				return -1;

			g_HardBp[i].lpAddress = (DWORD)lpAddress;
			g_HardBp[i].nType = nType;
			g_HardBp[i].nLen = nLen;
			g_HardBp[i].IsEnable = 1;


			DR7 Dr7 = { 0 };
			Dr7.val = Context.Dr7;
			switch (i) {
			case 0:
				Context.Dr0 = g_HardBp[i].lpAddress;
				Dr7.RW0 = g_HardBp[i].nType;
				Dr7.LEN0 = g_HardBp[i].nLen;
				Dr7.L0 = 1;   // set L0 = 1, don't set G0
				break;
			case 1:
				Context.Dr1 = g_HardBp[i].lpAddress;
				Dr7.RW1 = g_HardBp[i].nType;
				Dr7.LEN1 = g_HardBp[i].nLen;
				Dr7.L1 = 1;
				break;
			case 2:
				Context.Dr2 = g_HardBp[i].lpAddress;
				Dr7.RW2 = g_HardBp[i].nType;
				Dr7.LEN2 = g_HardBp[i].nLen;
				Dr7.L2 = 1;
				break;
			case 3:
				Context.Dr3 = g_HardBp[i].lpAddress;
				Dr7.RW3 = g_HardBp[i].nType;
				Dr7.LEN3 = g_HardBp[i].nLen;
				Dr7.L3 = 1;
				break;
			}


			Context.Dr7 = Dr7.val;
			if (MyWriteRegisters(dwThreadId, &Context) < 0)
				return -1;
			return 0;
		}
	}


	printf("DR Register Full\n");

	return 0;
}

int MyResetBreakHard(DWORD dwThreadId, HardBp hbpLst[4])
{

	for (int i = 0; i < 4; i++) {
		if (hbpLst[i].IsEnable && hbpLst[i].nType == 0) {
			CONTEXT Context;
			if (MyReadRegisters(dwThreadId, &Context) < 0)
				return -1;
			DR7 Dr7 = { 0 };
			Dr7.val = Context.Dr7;
			switch (i) {
			case 0:
				Context.Dr0 = g_HardBp[i].lpAddress;
				Dr7.RW0 = g_HardBp[i].nType;
				Dr7.LEN0 = g_HardBp[i].nLen;
				Dr7.L0 = 1;   // set L0 = 1, don't set G0
				break;
			case 1:
				Context.Dr1 = g_HardBp[i].lpAddress;
				Dr7.RW1 = g_HardBp[i].nType;
				Dr7.LEN1 = g_HardBp[i].nLen;
				Dr7.L1 = 1;
				break;
			case 2:
				Context.Dr2 = g_HardBp[i].lpAddress;
				Dr7.RW2 = g_HardBp[i].nType;
				Dr7.LEN2 = g_HardBp[i].nLen;
				Dr7.L2 = 1;
				break;
			case 3:
				Context.Dr3 = g_HardBp[i].lpAddress;
				Dr7.RW3 = g_HardBp[i].nType;
				Dr7.LEN3 = g_HardBp[i].nLen;
				Dr7.L3 = 1;
				break;
			}


			Context.Dr7 = Dr7.val;
			if (MyWriteRegisters(dwThreadId, &Context) < 0)
				return -1;
		}
	}
	return 0;
}

int MyRemoveBreakHard(DWORD dwThreadId, int nIndex)
{
	// if the hardware bp is not set notify the user
	if (!g_HardBp[nIndex].IsEnable) {
		LOGI("Break point is not enabled.");
	}

	CONTEXT Context;
	if (MyReadRegisters(dwThreadId, &Context) < 0)
		return -1;

	// to remove the hardware bp, set Lx to 0
	DR7 Dr7 = { 0 };
	Dr7.val = Context.Dr7;
	switch (nIndex) {
	case 0:
		Dr7.L0 = 0;
		Context.Dr0 = 0;
		break;
	case 1:
		Dr7.L1 = 0;
		Context.Dr1 = 0;
		break;
	case 2:
		Dr7.L2 = 0;
		Context.Dr2 = 0;
		break;
	case 3:
		Dr7.L3 = 0;
		Context.Dr3 = 0;
		break;
	}

	Context.Dr7 = Dr7.val;
	if (MyWriteRegisters(dwThreadId, &Context) < 0)
		return -1;

	// clear the entry in g_HardBp
	g_HardBp[nIndex].IsEnable = 0;
	g_HardBp[nIndex].lpAddress = 0;
	g_HardBp[nIndex].nLen = 0;
	g_HardBp[nIndex].nType = 0;

	return 0;
}

int MySetBreakMem(DWORD dwProcessId, LPVOID lpAddress, char chType, UINT nSize)
{
	//check if the page is valid
	if (!IsPageCommitted) {
		printf("Memory is not committed.");
		return -1;
	}
	//create a MemBp obj
	MemBp mbp;
	mbp.nId = g_nBmpIdCount;
	mbp.chType = chType;
	mbp.nLen = nSize;
	mbp.lpAddress = lpAddress;

	// iterate g_pages list, if any of bp's page is not in the list, add it to the list and change the protection constant
	DWORD startPage = (DWORD)lpAddress & 0xfffff000;
	DWORD endPage = ((DWORD)lpAddress + nSize - 1) & 0xfffff000;
	for (DWORD curPage = startPage; curPage <= endPage; curPage += 0x1000) {
		if (!IsPageExists(LPVOID(curPage))) {
			// page is not included in the g_pages list
				// change the protection constant for the page and add to the list
			DWORD memOldProtect;
			if (MyVirtualProtectEx(dwProcessId, (LPVOID)curPage, 0x1000, PAGE_NOACCESS, &memOldProtect) == -1) {
				return 0;
			}
			AddToPageList((LPVOID)curPage, memOldProtect);
		}
		// add current page to bpPageMapping list
		AddToBpPageMapping(mbp.nId, (LPVOID)curPage);
	}
	// add bp to g_memBps list
	g_memBps.push_back(mbp);
	//update bp id count
	g_nBmpIdCount++;
	return 0;
}

int MyVirtualProtectEx(DWORD dwPid, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	//修改内存属性
	int nResult = 0;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL) {
		ShowErrMsg("OpenProcess");
		return -1;
	}

	if (!VirtualProtectEx(hProcess,
		lpAddress,
		dwSize,
		flNewProtect,
		lpflOldProtect)) {
		ShowErrMsg("VirtualProtectEx");
		nResult = -1;
	}

    CloseHandle(hProcess);
	return nResult;
}

int MyRemoveBreakMem(int nIndex)
{
	if (nIndex < 0 || nIndex >= g_memBps.size()) {
		printf("Invalid index.");
		return -1;
	}
	auto it = g_memBps.begin();
	std::advance(it, nIndex);

	//delete bp from g_memBps
	DWORD deletedId = it->nId;
	g_memBps.erase(it);
	return deletedId;
}

std::list<LPVOID> MyRemoveBpPageMapping(int nId)
{
	//save bp's pages in a list
	std::list<LPVOID> bpPages;
	auto it = g_bpPageMappings.begin();
	while (it != g_bpPageMappings.end()) {
		if (it->nId == nId) {
			bpPages.push_back(it->lpPageAddress);
			it = g_bpPageMappings.erase(it);
		}
		else {
			++it;
		}
	}
	return bpPages;
}

DWORD MyRemovePages(LPVOID lpAddress)
{
	DWORD dwProtect;
	auto it = g_pages.begin();
	while (it != g_pages.end()) {
		if ((*it).lpBaseAddress == lpAddress) {
			dwProtect = (*it).oldProtect;
			it = g_pages.erase(it);
		}
		else {
			++it;
		}
	}
	return dwProtect;
}

bool IsMemBpExists(LPVOID lpAddress, char chType, UINT nLen)
{
	for (const auto& bp : g_memBps) {
		if (bp.lpAddress == lpAddress &&
			bp.chType == chType &&
			bp.nLen == nLen) {
			return true;
		}
	}
	return false;
}

//check if the page is committed
bool IsPageCommitted(DWORD dwProcessId, LPVOID lpAddress, UINT nLen)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
	if (hProcess == NULL) {
		LOGE("IsPageCommitted: OpenProcess");
		return false;
	}
	DWORD startPage = (DWORD)lpAddress & 0xfffff000;
	DWORD endPage = ((DWORD)lpAddress + nLen - 1) & 0xfffff000;
	// iterate all pages
	for (DWORD curPage = startPage; curPage <= endPage; curPage += 0x1000) {
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		if (VirtualQueryEx(hProcess,
			LPVOID(curPage),
			&mbi,
			sizeof(mbi)) == 0) {
			return false;
		}
		if (mbi.State != MEM_COMMIT) {
			return false;
		}
	}
	return true;
}

bool IsPageExists(LPVOID lpBaseAddress)
{
	for (const auto& page : g_pages) {
		if ((DWORD)page.lpBaseAddress == (DWORD)lpBaseAddress) {
			return true;
		}
	}
	return false;
}

int AddToPageList(LPVOID lpAddress, DWORD dwOldProtect)
{
	PageInfo page;
	page.lpBaseAddress = lpAddress;
	page.oldProtect = dwOldProtect;
	g_pages.push_back(page);
	return 0;
}

int AddToBpPageMapping(DWORD nId, LPVOID lpBaseAddress)
{
	BpPageMapping bpm;
	bpm.nId = nId;
	bpm.lpPageAddress = lpBaseAddress;
	g_bpPageMappings.push_back(bpm);
	return 0;
}

std::list<UINT> IsPageInBpPageMapping(DWORD lpAddress)
{
	//Create a list to save the results
	std::list<UINT> lstResult;
	for (const auto& bpm : g_bpPageMappings) {
		if ((lpAddress & 0xfffff000) == (DWORD)bpm.lpPageAddress) {
			lstResult.push_back(bpm.nId);
		}
	}
	return lstResult;
}

bool IsPageUsedByOtherBps(LPVOID lpAddress)
{
	for (const auto& bpm : g_bpPageMappings) {
		if (bpm.lpPageAddress == lpAddress) {
			return true;
		}
	}
	return false;
}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		Help();
		return 0;
	}
	for (int i = 1; i < argc; i++) {
		if (strncmp(argv[i], "-exec", 6) == 0) {
			//start debugging
			DebugApp(argv[i + 1]);
		}
	}
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu
 // Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
