#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <string>
#include <fstream>
#include <sstream>
#include <ostream>
#include <conio.h>
#include <wininet.h>
#include <Winternl.h>
#include <iostream>
#include "tchar.h"
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
bool CreateRemoteThreadMethod(unsigned int pid, const char* dll_path) {

	HANDLE process;
	process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);

	LPVOID loadLibraryAddress;
	loadLibraryAddress = LPVOID(GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"));

	LPVOID memory;
	memory = LPVOID(VirtualAllocEx(process, nullptr, strlen(dll_path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));

	WriteProcessMemory(process, LPVOID(memory), dll_path, strlen(dll_path) + 1, nullptr);
	CreateRemoteThread(process, nullptr, NULL, LPTHREAD_START_ROUTINE(loadLibraryAddress), LPVOID(memory), NULL, nullptr);

	CloseHandle(process);
	VirtualFreeEx(process, LPVOID(memory), 0, MEM_RELEASE);

	return true;
}

void DownloadServicediver()
{

	HANDLE _File = CreateFileA("C://Windows//Temp//KAOXD.bat", GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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
		L"C://Windows//Temp//KAOXD.bat",            // path to service's binary
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

string random(int len)
{

	string a = /*abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*/XorStr<0x76, 63, 0x784652B1>("\x17\x15\x1B\x1D\x1F\x1D\x1B\x15\x17\x15\xEB\xED\xEF\xED\xEB\xF5\xF7\xF5\xFB\xFD\xFF\xFD\xFB\xF5\xF7\xF5\xD1\xD3\xD1\xD7\xD1\xD3\xD1\xDF\xD1\xD3\xD1\xD7\xD1\xD3\xD1\xCF\xF1\xF3\xF1\xF7\xF1\xF3\xF1\xFF\xF1\xF3\x9A\x9A\x9E\x9E\x9A\x9A\x86\x86\x8A\x8A" + 0x784652B1).s;
	string r;
	srand(time(NULL));
	for (int i = 0; i < len; i++) r.push_back(a.at(size_t(rand() % 62)));
	return r;

}

void AddressDllinjector()
{

	HANDLE _File = CreateFileA("C://Windows//Temp//PUBGMobile.tmp", GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(_File, (PVOID)rawData, sizeof(rawData), new ULONG, NULL);
	CloseHandle(_File);
	SetFileAttributes("C://Windows//Temp//KAOXD.bat", FILE_ATTRIBUTE_HIDDEN); //diver
	SetFileAttributes("C://Windows//Temp//PUBGMobile.tmp", FILE_ATTRIBUTE_HIDDEN);//dll hack


}

DWORD ReadyToInjectz(DWORD dwPID) {

	VMProtectBegin("KAOXD");
	if (dwPID) {


		Sleep(50);
		CreateRemoteThreadMethod(dwPID, "C://Windows//Temp//PUBGMobile.tmp");

		system(XorStr<0x66, 15, 0x53F63BCC>("\x08\x02\x1C\x49\x19\x1F\x03\x1D\x4E\x24\x31\x3E\x2A\x37" + 0x53F63BCC).s);
		Sleep(50);
		system(XorStr<0xAA, 18, 0xA4851AB5>("\xD9\xC8\x8C\xC9\xCB\xC3\xD5\xC5\xD7\x93\x96\xFE\xF7\xF8\xE0\xFD\x98" + 0xA4851AB5).s);
		ExitProcess(1);
	}
	VMProtectEnd();
	return 0;
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
HMODULE hModule;
DWORD pid, pid2, pid3, pid4, pid5,pid6;
int main(int argc, char *argv[])
{
	char pa[999];
	sprintf(pa, "%s", argv[1]);
	TCHAR CopyFileName1[2048] = { 0 };
	if (strcmp(pa, "(null)") == 0)
	{
		TCHAR CopyFileName[2048] = { 0 };

		GetModuleFileName(NULL, CopyFileName, MAX_PATH);

		GetModuleFileName(NULL, CopyFileName1, MAX_PATH);

		char *End;

		End = strrchr(CopyFileName, ('\\')) + 1;

		if (!End)
			return FALSE;

		*End = ('\0');

		char txt[999];
		sprintf(txt, "%s%s.exe", CopyFileName, random(20));

		char txt1[999];
		sprintf(txt1, "\"%s\"", CopyFileName1);

		CopyFile(CopyFileName1, txt, false);
		//MessageBox(0,txt,"",0);

		ShellExecute(NULL, "open", txt, txt1, NULL, SW_SHOW);

		return 0;
	}
	else
	{

		Sleep(200);
		char Delete[999];
		strcpy(Delete, argv[1]);
		remove(Delete);

		DownloadServicediver();
		CreateServicediver();
		AddressDllinjector();

			SetConsoleTitle(TEXT("== BuffaloTH ==\n"));

			Sleep(1000);

			_cprintf(" \n[+] %s \n\n", __TIMESTAMP__);
			//printf("[+]" " HWID: %s\n", hwProfileInfo.szHwProfileGuid);;
			DoSome();
			system("color F");
			Sleep(500);
			_cprintf("[+]"" Dowland Successfull.\n");
			Sleep(500);
			_cprintf("[+]"" Please enter the game.\n");
			ShellExecute(NULL, "open", "https://www.facebook.com/BuffaloTHz/", NULL, NULL, SW_SHOW);

			CreateMutexA(0, FALSE, XorStr<0x6E, 18, 0x81F7B094>("\x22\x00\x13\x10\x1E\x2F\x50\x18\x0F\x07\x0A\x16\x1D\x09\x1D\x10\x5A" + 0x81F7B094).s); // try to create a named mutex
			if (GetLastError() == ERROR_ALREADY_EXISTS)
				return -1;



			//system(/*start diver KAOXD*/XorStr<0xCE, 19, 0xB4F2EF50>("\xBD\xAC\xFE\xB4\xAA\xB6\xF4\xA6\xA2\xB6\xAA\xAD\xFA\x90\x9D\x92\x86\x9B" + 0xB4F2EF50).s); //
		
			while (!pid)
			{
				pid = DumpScanV1();
			}

			while (!pid2)
			{
				pid2 = DumpScanV1();

				if (pid2 == pid)
				{
					pid2 = 0;
				}

			}


		if (1){
			
			ReadyToInjectz(pid2);
		}
	
	}
	return 0;
}