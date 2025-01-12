#pragma once
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h> 
#include <list>
#pragma comment(lib, "dasm.lib")

#define LOGD(fmt, ...) printf("[DEBUG] "##fmt, __VA_ARGS__)
#define LOGE(fmt, ...) printf("[ERROR] "##fmt, __VA_ARGS__)
#define LOGI(fmt, ...) printf("[INFO] "##fmt, __VA_ARGS__)
#define LOGW(fmt, ...) printf("[WARNING] "##fmt, __VA_ARGS__)

#define EFLAGS_TF 0x100

struct stCommand {
	const char* cmd;
	int (*pfn)(DEBUG_EVENT* lpEvent, const char* lpCmd);
};

//Register DR7
typedef union _DR7 {
    struct {
        unsigned L0 : 1;
        unsigned G0 : 1;
        unsigned L1 : 1;
        unsigned G1 : 1;
        unsigned L2 : 1;
        unsigned G2 : 1;
        unsigned L3 : 1;
        unsigned G3 : 1;
        unsigned LE : 1;
        unsigned GE : 1;
        unsigned RES1 : 3;
        unsigned GD : 1;
        unsigned RES2 : 2;
        unsigned RW0 : 2;
        unsigned LEN0 : 2;
        unsigned RW1 : 2;
        unsigned LEN1 : 2;
        unsigned RW2 : 2;
        unsigned LEN2 : 2;
        unsigned RW3 : 2;
        unsigned LEN3 : 2;
    };
    unsigned val;
}DR7;

//Register DR6
typedef union _DR6 {
    struct {
        unsigned B0 : 1;
        unsigned B1 : 1;
        unsigned B2 : 1;
        unsigned B3 : 1;
        unsigned RES1 : 9;
        unsigned BD : 1;
        unsigned BS : 1;
        unsigned BT : 1;
        unsigned RES2 : 16;
    };
    unsigned val;
}DR6;

//software breakpoint
typedef struct _SoftBp {
    LPVOID lpAddress;
    BYTE originalByte; 
    bool IsEnable;
    bool oneTime; // one-shot breakpoint
}SoftBp;


// hardware breakpoint
typedef struct _HardBp {
    DWORD IsEnable; //status of bp
    DWORD lpAddress;
    DWORD nType;
    DWORD nLen;
}HardBp;

// memory bp
// memory bp Information 
typedef struct _MemBp {
    DWORD nId;  // id of the bp
    LPVOID lpAddress; // address of bp
    char chType; // Access('a') or write ('w') 
    UINT nLen; // length of bp
}MemBp;

// Page information
typedef struct _PageInfo {
    LPVOID lpBaseAddress; // The starting address of the page 
    DWORD oldProtect;    // The original memory protection option.
}PageInfo;

// Memory bp - Page Mapping
typedef struct _BpPageMapping {
    DWORD nId; // bp id
    LPVOID lpPageAddress; // address of the page
}BpPageMapping;

void Help();
int ShowErrMsg(const char* lpFunName);
int DebugApp(const char* lpApplicationName, char* lpCommand = NULL);

// FUNCTIONS TO HANDLE DEBUG EVENTS.
DWORD EventExec(DEBUG_EVENT* lpEvent);
DWORD EventCreateProcess(DEBUG_EVENT* lpEvent);
DWORD EventExitProcess(DEBUG_EVENT* lpEvent);
DWORD EventCreateThread(DEBUG_EVENT* lpEvent);
DWORD EventExitThread(DEBUG_EVENT* lpEvent);
DWORD EventLoadDll(DEBUG_EVENT* lpEvent);
DWORD EventUnloadDll(DEBUG_EVENT* lpEvent);
DWORD EventOutputString(DEBUG_EVENT* lpEvent);
DWORD EventRip(DEBUG_EVENT* lpEvent);

//Exception Handling
DWORD ExecBreakPoint(DEBUG_EVENT* lpEvent);
DWORD ExecStep(DEBUG_EVENT* lpEvent);
int GetCommand(DEBUG_EVENT* lpEvent);
DWORD ExecPriv(DEBUG_EVENT* lpEvent);
DWORD ExecAccess(DEBUG_EVENT* lpEvent);
//Import Disassembly function from an open-source disassembler "dasm"
extern "C"
void __stdcall Decode2Asm(IN PBYTE pCodeEntry,
	OUT char* strAsmCode,
	OUT UINT * pnCodeSize,
	UINT nAddress);

int MyDisAsm(DWORD dwProcessId, LPVOID lpAddress, UINT nLine);
int MyShowReg(DWORD dwThreadId);
int MyModifyReg(DWORD dwThreadId, char* szReg);
int MyShowSpecReg(DWORD dwThreadId, char* szReg);
int MyReadRegisters(DWORD dwThreadId, CONTEXT* pContext);
int MyWriteRegisters(DWORD dwThreadId, CONTEXT* pContext);
int MyReadProcessMemory(DWORD dwProcessId, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize);
int MyWriteProcessMemory(DWORD dwProcessId, LPVOID lpBase, LPVOID lpBuffer, SIZE_T nSize);
int MySetStep(DWORD dwThreadId);
int MySetBreakPoint(DWORD dwProcessId, UINT nType, LPVOID lpAddress);
int MySetBreakHard(DWORD dwThreadId, LPVOID lpAddress, UINT nType, UINT nLen);
int MyResetBreakHard(DWORD dwThreadId, HardBp hbpLst[4]);
int MyRemoveBreakHard(DWORD dwThreadId, int nIndex);
int MySetBreakMem(DWORD dwProcessId, LPVOID lpAddress, char chType, UINT nSize);
int MyVirtualProtectEx(DWORD dwPid,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flNewProtect,
	PDWORD lpflOldProtect
);

// assistant function for Memory BP
int MyRemoveBreakMem(int nIndex);
std::list<LPVOID> MyRemoveBpPageMapping(int nId);
DWORD MyRemovePages(LPVOID lpAddress);
bool IsMemBpExists(LPVOID lpAddress, char charType, UINT nLen); // if breakpoint exists in g_memBps list
bool IsPageCommitted(DWORD dwProcessId, LPVOID lpAddress, UINT nLen); //if involved page is committed
bool IsPageExists(LPVOID lpAddress); // if a given page exists in g_pages list
int AddToPageList(LPVOID lpAddress, DWORD dwOldProtect);
int AddToBpPageMapping(DWORD nId, LPVOID lpBaseAddress);
std::list<UINT> IsPageInBpPageMapping(DWORD lpAddress); // check if the exception is in the same page as any of the bp.
bool IsPageUsedByOtherBps(LPVOID lpAddress);
//Command 
DWORD GetOldProtect(DWORD lpAddress);


int CmdDisAsm(DEBUG_EVENT* lpEvent, const char* lpCmd);
int CmdRun(DEBUG_EVENT* lpEvent, const char* lpCmd);
int CmdExecTillRet(DEBUG_EVENT* lpEvent, const char* lpCmd); // execute till return
int CmdRegister(DEBUG_EVENT* lpEvent, const char* lpCmd);
int CmdStep(DEBUG_EVENT* lpEvent, const char* lpCmd);
int CmdNext(DEBUG_EVENT* lpEvent, const char* lpCmd); 
int CmdBreakPoint(DEBUG_EVENT* lpEvent, const char* lpCmd); // software breakpoint
int CmdBreakPointList(DEBUG_EVENT* lpEvent, const char* lpCmd); // show  a list of software breakpoint
int CmdBreakPointClear(DEBUG_EVENT* lpEvent, const char* lpCmd); // show  a list of software breakpoint
int CmdBreakMem(DEBUG_EVENT* lpEvent, const char* lpCmd); 
int CmdBreakMemList(DEBUG_EVENT* lpEvent, const char* lpCmd); 
int CmdBreakMemClear(DEBUG_EVENT* lpEvent, const char* lpCmd);
int CmdBreakHard(DEBUG_EVENT* lpEvent, const char* lpCmd);
int CmdBreakHardList(DEBUG_EVENT* lpEvent, const char* lpCmd);
int CmdBreakHardClear(DEBUG_EVENT* lpEvent, const char* lpCmd);
int CmdDisplayMemory(DEBUG_EVENT* lpEvent, const char* lpCmd);
int CmdModifyMemory(DEBUG_EVENT* lpEvent, const char* lpCmd);
int CmdListModules(DEBUG_EVENT* lpEvent, const char* lpCmd);