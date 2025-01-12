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
DWORD ExecBreakPoint(DEBUG_EVENT* lpEvent);   //handle EXCEPTION_BREAKPOINT
DWORD ExecStep(DEBUG_EVENT* lpEvent);  // handle EXCEPTION_SINGLE_STEP
int GetCommand(DEBUG_EVENT* lpEvent);  // get commands from command line
DWORD ExecPriv(DEBUG_EVENT* lpEvent);  //handle EXCEPTION_PRIV_INSTRUCTION
DWORD ExecAccess(DEBUG_EVENT* lpEvent); //handle EXCEPTION_ACCESS_VIOLATION
//Import Disassembly function from an open-source disassembler "dasm"
extern "C"
void __stdcall Decode2Asm(IN PBYTE pCodeEntry,
	OUT char* strAsmCode,
	OUT UINT * pnCodeSize,
	UINT nAddress);

int MyDisAsm(DWORD dwProcessId, LPVOID lpAddress, UINT nLine);  // disassembly
int MyShowReg(DWORD dwThreadId);     //show registers
int MyModifyReg(DWORD dwThreadId, char* szReg);  //modify registers
int MyShowSpecReg(DWORD dwThreadId, char* szReg);  //show a specified register
int MyReadRegisters(DWORD dwThreadId, CONTEXT* pContext);  // read registers
int MyWriteRegisters(DWORD dwThreadId, CONTEXT* pContext);  // write registers
int MyReadProcessMemory(DWORD dwProcessId, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize);  // read process memory
int MyWriteProcessMemory(DWORD dwProcessId, LPVOID lpBase, LPVOID lpBuffer, SIZE_T nSize);  //write process memory
int MySetStep(DWORD dwThreadId);  // set single step 
int MySetBreakPoint(DWORD dwProcessId, UINT nType, LPVOID lpAddress); // set software bp
int MySetBreakHard(DWORD dwThreadId, LPVOID lpAddress, UINT nType, UINT nLen);  //set hardware bp
int MyResetBreakHard(DWORD dwThreadId, HardBp hbpLst[4]);  // reset hardware bp
int MyRemoveBreakHard(DWORD dwThreadId, int nIndex);   //delete hardware bp
int MySetBreakMem(DWORD dwProcessId, LPVOID lpAddress, char chType, UINT nSize);  // set memory bp
int MyRemoveBreakMem(int nIndex);   // delete memory bp
int MyVirtualProtectEx(DWORD dwPid,    
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flNewProtect,
	PDWORD lpflOldProtect
);  // change memory protection options

// assistant function for Memory Bp
std::list<LPVOID> MyRemoveBpPageMapping(int nId);  // remove an element from BP-Page mappling
DWORD MyRemovePages(LPVOID lpAddress);  // remove an element from page list
bool IsMemBpExists(LPVOID lpAddress, char charType, UINT nLen); // if breakpoint exists in g_memBps list
bool IsPageCommitted(DWORD dwProcessId, LPVOID lpAddress, UINT nLen); //if involved page is committed
bool IsPageExists(LPVOID lpAddress); // if a given page exists in g_pages list
int AddToPageList(LPVOID lpAddress, DWORD dwOldProtect);  // add an element to page list
int AddToBpPageMapping(DWORD nId, LPVOID lpBaseAddress); // add an element to bp-page mapping
std::list<UINT> IsPageInBpPageMapping(DWORD lpAddress); // check if the exception is in the same page as any of the bp.
bool IsPageUsedByOtherBps(LPVOID lpAddress);  // check if pages are used by other break point
//Command 
DWORD GetOldProtect(DWORD lpAddress);  // get the old memory protection constant for a page


//Commands
int CmdDisAsm(DEBUG_EVENT* lpEvent, const char* lpCmd);  // u: show disassembly
int CmdRun(DEBUG_EVENT* lpEvent, const char* lpCmd);  // g: run 
int CmdExecTillRet(DEBUG_EVENT* lpEvent, const char* lpCmd); // ret: execute till return
int CmdRegister(DEBUG_EVENT* lpEvent, const char* lpCmd); //r : show/ modify registers
int CmdStep(DEBUG_EVENT* lpEvent, const char* lpCmd); // t: step in
int CmdNext(DEBUG_EVENT* lpEvent, const char* lpCmd); // p: step over
int CmdBreakPoint(DEBUG_EVENT* lpEvent, const char* lpCmd); // bp: set software breakpoint
int CmdBreakPointList(DEBUG_EVENT* lpEvent, const char* lpCmd); // bl: show  a list of software breakpoint
int CmdBreakPointClear(DEBUG_EVENT* lpEvent, const char* lpCmd); // bc: delete  a list of software breakpoint
int CmdBreakMem(DEBUG_EVENT* lpEvent, const char* lpCmd);   // bm: set a memory bp
int CmdBreakMemList(DEBUG_EVENT* lpEvent, const char* lpCmd); // bml: show a list of memory bp
int CmdBreakMemClear(DEBUG_EVENT* lpEvent, const char* lpCmd);  // bmc: delete memory bp
int CmdBreakHard(DEBUG_EVENT* lpEvent, const char* lpCmd);  //ba: set a hardware bp
int CmdBreakHardList(DEBUG_EVENT* lpEvent, const char* lpCmd); // bal: show a list of hardware bp
int CmdBreakHardClear(DEBUG_EVENT* lpEvent, const char* lpCmd); //bac: delete a hardware bp
int CmdDisplayMemory(DEBUG_EVENT* lpEvent, const char* lpCmd); // dd: display memory
int CmdModifyMemory(DEBUG_EVENT* lpEvent, const char* lpCmd); // ed: modify memory
int CmdListModules(DEBUG_EVENT* lpEvent, const char* lpCmd); // lm: list modules