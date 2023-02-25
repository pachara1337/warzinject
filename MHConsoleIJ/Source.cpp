#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <iostream>
#include <limits>
#include <iostream>
#include <limits>
#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include <intrin.h>
using namespace std;
#include  <iostream>
#include <stdio.h>
#include <stdlib.h>
#include<conio.h>
#include<stdlib.h>
#include <errno.h>
#include <Windows.h>

#include <sys/types.h>

using namespace std;
#include <string>
#include <fstream>
#include  <iostream>
#include <sstream>
#include <ostream>
#include <conio.h>
#include <wininet.h>
#include <iostream>
using namespace std;
#include <Winternl.h>
#include <iostream>
#include "tchar.h"
#include <string>
#include <iostream>
#include <thread>
#include <wininet.h>
#include <winsock.h>

#include <urlmon.h>

#include <time.h>
#include <psapi.h>
#include <sddl.h>
#include <accctrl.h>
#include <aclapi.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wsock32.lib")
#pragma comment (lib,"wininet.lib")
#pragma comment (lib, "urlmon.lib")
#pragma comment(lib, "shlwapi.lib")
using namespace std;
#include "VMProtectSDK.h"

#pragma comment(lib,"Kaoxd.lib")
#include "Console.h"
#include "Xorstr.h"
#include "KAOXD.h"
#include "GetProcess.h"


#include "DllData.h"
typedef HINSTANCE(*fpLoadLibrary)(char*);

//
bool CreateRemoteThreadMethod(unsigned int pid, const char* dll_path) {

	HANDLE process;
	process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);

	LPVOID loadLibraryAddress;
	loadLibraryAddress = LPVOID(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA"));

	LPVOID memory;
	memory = LPVOID(VirtualAllocEx(process, nullptr, strlen(dll_path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));

	WriteProcessMemory(process, LPVOID(memory), dll_path, strlen(dll_path) + 1, nullptr);
	Sleep(1);
	CreateRemoteThread(process, nullptr, NULL, LPTHREAD_START_ROUTINE(loadLibraryAddress), LPVOID(memory), NULL, nullptr);
	SuspendThread(process);
	CloseHandle(process);

	VirtualFreeEx(process, LPVOID(memory), 0, MEM_RELEASE);

	return 1;
}




bool CreateRemoteThreadMethod1(unsigned int pid, const char* dll_path) {

	HANDLE process;
	process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);

	LPVOID loadLibraryAddress;
	loadLibraryAddress = LPVOID(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA"));

	LPVOID memory;
	memory = LPVOID(VirtualAllocEx(process, nullptr, strlen(dll_path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));

	WriteProcessMemory(process, LPVOID(memory), dll_path, strlen(dll_path) + 1, nullptr);
	Sleep(1);
	CreateRemoteThread(process, nullptr, NULL, LPTHREAD_START_ROUTINE(loadLibraryAddress), LPVOID(memory), NULL, nullptr);
	SuspendThread(process);
	CloseHandle(process);

	VirtualFreeEx(process, LPVOID(memory), 0, MEM_RELEASE);

	return 1;
}

void DownloadServicediver()
{

	HANDLE _File = CreateFileA("C://Windows//Temp//KAOXD.sys", GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(_File, (PVOID)KAOXD, sizeof(KAOXD), new ULONG, NULL);
	CloseHandle(_File);

}

void CreateServicediver()
{

	SC_HANDLE h_manager = NULL;
	SC_HANDLE h_service = NULL;

	h_manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	h_service = CreateServiceW(
		h_manager,                 // SCM database
		L"KAOXD",
		L"KAOXD",
		SERVICE_ALL_ACCESS,        // desired access
		SERVICE_KERNEL_DRIVER, // service type         
		SERVICE_AUTO_START,        // start type
		SERVICE_ERROR_SEVERE,      // error control type
		L"C://Windows//Temp//KAOXD.sys",            // path to service's binary
		NULL,                      /* no load ordering group  */
		NULL,                      /* no tag identifier       */
		NULL,                      /* no dependencies         */
		NULL,                      /* LocalSystem account     */
		NULL

	);
	CloseServiceHandle(h_service);
	CloseServiceHandle(h_manager);



}

DWORD killProcessByName(const char *filename)
{

	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	DWORD dwGetProcessID = 0;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, filename) == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, (DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				dwGetProcessID = TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);

	return dwGetProcessID;
	
}








void rndmTitle() {
	constexpr int length = 15;
	const auto characters = TEXT("abcdefghi9182345jklmnopqrstuv211935960473wxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890");
	TCHAR title[length + 1]{};

	for (int j = 0; j != length; j++)
	{
		title[j] += characters[rand() % 80];
	}

	SetConsoleTitle(title);
}








void AddressDllinjector()
{

	HANDLE _File = CreateFileA("C://Windows//SysWOW64//XAPOFX1_0.dll", GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(_File, (PVOID)rawData, sizeof(rawData), new ULONG, NULL);
	CloseHandle(_File);
	SetFileAttributes("C://Windows//Temp//KAOXD.sys", FILE_ATTRIBUTE_HIDDEN); //diver
	SetFileAttributes("C://Windows//SysWOW64//XAPOFX1_0.dll", FILE_ATTRIBUTE_HIDDEN);//dll hack


}





















DWORD dwGetProcessID(PCHAR szProcName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	DWORD dwGetProcessID = 0;
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 ProcEntry32 = { 0 };
		ProcEntry32.dwSize = sizeof(MODULEENTRY32);
		if (Process32First(hSnapshot, &ProcEntry32)) {
			do {
				if (strcmp(ProcEntry32.szExeFile, szProcName) == 0) {
					dwGetProcessID = (DWORD)ProcEntry32.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnapshot, &ProcEntry32));
		}
		CloseHandle(hSnapshot);
	}
	return dwGetProcessID;//2004
}

DWORD pid, pid2, pid3, pid4, pid5, pid6;















DWORD ReadyToInjectz(DWORD dwPID) {
	//VMProtectBegin("KAOXD");
	if (dwPID) {
	
	

		CreateRemoteThreadMethod(dwPID, "C://Windows//SysWOW64//XAPOFX1_0.dll");
		//Sleep(20000);
//	ปิด driver
	//	system(XorStr<0x66, 15, 0x53F63BCC>("\x08\x02\x1C\x49\x19\x1F\x03\x1D\x4E\x24\x31\x3E\x2A\x37" + 0x53F63BCC).s);
	//	Sleep(50);
		//system(XorStr<0xAA, 18, 0xA4851AB5>("\xD9\xC8\x8C\xC9\xCB\xC3\xD5\xC5\xD7\x93\x96\xFE\xF7\xF8\xE0\xFD\x98" + 0xA4851AB5).s);
		ExitProcess(1);
	}
//VMProtectEnd();
	return 0;
}

HMODULE hModule;




	

bool PromptForChar(const char* prompt, char& readch)
{
	std::string tmp;
	std::cout << prompt << std::endl;
	if (std::getline(std::cin, tmp))
	{
		// Only accept single character input
		if (tmp.length() == 1)
		{
			readch = tmp[0];
		}
		else
		{
			// For most input, char zero is an appropriate sentinel
			readch = '\0';
		}
		return true;
	}
	return false;
}


int main(int argc, char* argv[])
{

    


 remove("C://Windows//SysWOW64//XAPOFX1_0.dll");
    Sleep(500);

    DownloadServicediver();
    CreateServicediver();
    AddressDllinjector();

	


    while (1)
    {
     

        MessageBox(0, "กดเข้าเกม ไปลุยกันเลย", "", MB_OK)
			;
	

     //   Beep(950, 500);
      //  Beep(850, 400);

  //      system("sc stop vgk>nul");
		//system("sc start KAOXD>nul");
            //CreateMutexA(0, FALSE, XorStr<0x6E, 18, 0x81F7B094>("\x22\x00\x13\x10\x1E\x2F\x50\x18\x0F\x07\x0A\x16\x1D\x09\x1D\x10\x5A" + 0x81F7B094).s); // try to create a named mutex
            //if (GetLastError() == ERROR_ALREADY_EXISTS)
            //	return -1;
		FreeConsole();
		ShowWindow(GetConsoleWindow(), SW_HIDE);

            //system(/*start diver KAOXD*/XorStr<0xCE, 19, 0xB4F2EF50>("\xBD\xAC\xFE\xB4\xAA\xB6\xF4\xA6\xA2\xB6\xAA\xAD\xFA\x90\x9D\x92\x86\x9B" + 0xB4F2EF50).s); //




           
        while (!pid)
        {
            pid = DumpScanV1();
		
   

        }
      

        if (1) {


		
            ReadyToInjectz(pid);


        }

        return 0;
    }
}



	/////////////////////////////////////////////////////////////////////////////////////
	


