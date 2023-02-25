#pragma once
#include "DllData.h"

typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI *PDLL_MAIN)(HMODULE, DWORD, PVOID);

typedef struct _MANUAL_INJECT
{
	PVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
}MANUAL_INJECT, *PMANUAL_INJECT;
int map(unsigned int pid/*, LPCSTR dllname*/);

HANDLE NtCreateThreadEx(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpSpace)
{
	///The prototype of NtCreateThreadEx from undocumented.ntinternals.com
	typedef DWORD(WINAPI * functypeNtCreateThreadEx)(
		PHANDLE                 ThreadHandle,
		ACCESS_MASK             DesiredAccess,
		LPVOID                  ObjectAttributes,
		HANDLE                  ProcessHandle,
		LPTHREAD_START_ROUTINE  lpStartAddress,
		LPVOID                  lpParameter,
		BOOL                    CreateSuspended,
		DWORD                   dwStackSize,
		DWORD                   Unknown1,
		DWORD                   Unknown2,
		LPVOID                  Unknown3
		);

	HANDLE                      hRemoteThread = NULL;
	HMODULE                     hNtDllModule = NULL;
	functypeNtCreateThreadEx    funcNtCreateThreadEx = NULL;

	//Get handle for ntdll which contains NtCreateThreadEx
	hNtDllModule = GetModuleHandle("ntdll.dll");
	if (hNtDllModule == NULL)
	{
		std::cout << "Cannot get module  ntdll.dll  error: " << GetLastError() << std::endl;
		return NULL;
	}
	funcNtCreateThreadEx = (functypeNtCreateThreadEx)GetProcAddress(hNtDllModule, "NtCreateThreadEx");
	if (!funcNtCreateThreadEx)
	{
		std::cout << "Cannot get procedure address  error: " << GetLastError() << std::endl;
		return NULL;
	}
	funcNtCreateThreadEx(&hRemoteThread,  /*GENERIC_ALL*/0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpBaseAddress, lpSpace, FALSE, NULL, NULL, NULL, NULL);
//	std::cout << "Status NtSystemEx  " << GetLastError() << std::endl;
	//std::cout << "hRemoteThread:           " << hRemoteThread << std::endl;
	//std::cout << "hNtDllModule:            " << hNtDllModule << std::endl;
	//std::cout << "funcNtNtSystemEx:    " << funcNtCreateThreadEx << std::endl;
	return hRemoteThread;
}

DWORD WINAPI LoadDll(PVOID p)
{
	PMANUAL_INJECT ManualInject;

	HMODULE hModule;
	DWORD i, Function, count, delta;

	PDWORD ptr;
	PWORD list;

	PIMAGE_BASE_RELOCATION pIBR;
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	PIMAGE_IMPORT_BY_NAME pIBN;
	PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

	PDLL_MAIN EntryPoint;

	ManualInject = (PMANUAL_INJECT)p;

	pIBR = ManualInject->BaseRelocation;
	delta = (DWORD)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	// Relocate the image

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			list = (PWORD)(pIBR + 1);

			for (i = 0; i<count; i++)
			{
				if (list[i])
				{
					ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	pIID = ManualInject->ImportDirectory;

	// Resolve DLL imports

	while (pIID->Characteristics)
	{
		OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

		hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

		if (!hModule)
		{
			return FALSE;
		}

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal

				Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			else
			{
				// Import by name

				pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
				Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}

	return TRUE;
}

DWORD WINAPI LoadDllEnd()
{
	return 0;
}

int map(unsigned int pid)
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;

	HANDLE hProcess, hThread, hFile;
	PVOID buffer, image, mem;
	DWORD i, FileSize, ProcessId, ExitCode, read;

	//TOKEN_PRIVILEGES tp;
	MANUAL_INJECT ManualInject;

	//  _cprintf("\nOpening the DLL.\n");

	size_t dwSize = sizeof(rawData);

	//hFile = dwSize; // Open the DLL

	//if (hFile == INVALID_HANDLE_VALUE)
	//{
	//	//   _cprintf("\nError: Unable to open the DLL (%d)\n", GetLastError());

	//	return -1;
	//}

	PBYTE lpAddress = rawData;
	buffer = VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!buffer)
	{
		//  _cprintf("\nError: Unable to allocate memory for DLL data (%d)\n", GetLastError());

		CloseHandle(lpAddress);
		return -1;
	}

	// Read the DLL

	if (!memcpy((void*)buffer, (void*)lpAddress, dwSize)/*ReadFile(hFile, buffer, dwSize, &read, NULL)*/)
	{
		//    _cprintf("\nError: Unable to read the DLL (%d)\n", GetLastError());

		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(lpAddress);

		return -1;
	}

	CloseHandle(lpAddress);

	pIDH = (PIMAGE_DOS_HEADER)buffer;

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//  _cprintf("\nError: Invalid executable image.\n");

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);

	if (pINH->Signature != IMAGE_NT_SIGNATURE)
	{
		//  _cprintf("\nError: Invalid PE header.\n");

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
	{
		//   _cprintf("\nError: The image is not DLL.\n");

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	ProcessId = pid;

	//  _cprintf("\nOpening target process.\n");

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, ProcessId);

	if (!hProcess)
	{
		//  _cprintf("\nError: Unable to open target process (%d)\n", GetLastError());

		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		return -1;
	}

	//  _cprintf("\nAllocating memory for the DLL.\n");

	image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the DLL

	if (!image)
	{
		//  _cprintf("\nError: Unable to allocate memory for the DLL (%d)\n", GetLastError());

		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		return -1;
	}

	// Copy the header to target process

	//  _cprintf("\nCopying headers into target process.\n");

	if (!WriteProcessMemory(hProcess, image, buffer, pINH->OptionalHeader.SizeOfHeaders, NULL))
	{

		//  _cprintf("\nError: Unable to copy headers to target process (%d)\n", GetLastError());

		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;//KKKK
	}

	pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);

	// Copy the DLL to target process

	// _cprintf("\nCopying sections to target process.\n");

	for (i = 0; i < pINH->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(hProcess, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress), (PVOID)((LPBYTE)buffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL);
	}

	//  _cprintf("\nAllocating memory for the loader code.\n");

	mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code

	if (!mem)
	{

		// _cprintf("\nError: Unable to allocate memory for the loader code (%d)\n", GetLastError());

		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	// _cprintf("\nLoader code allocated at %#p\n", mem);

	memset(&ManualInject, 0, sizeof(MANUAL_INJECT));

	ManualInject.ImageBase = image;
	ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
	ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ManualInject.fnLoadLibraryA = LoadLibraryA;
	ManualInject.fnGetProcAddress = GetProcAddress;

	// _cprintf("\nWriting loader code to target process.\n");

	WriteProcessMemory(hProcess, mem, &ManualInject, sizeof(MANUAL_INJECT), NULL); // Write the loader information to target process
	WriteProcessMemory(hProcess, (PVOID)((PMANUAL_INJECT)mem + 1), LoadDll, (DWORD)LoadDllEnd - (DWORD)LoadDll, NULL); // Write the loader code to target process

	// _cprintf("\nExecuting loader code.\n");

	//hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PMANUAL_INJECT)mem + 1), mem, 0, NULL); // Create a remote thread to execute the loader code

	hThread = NtCreateThreadEx(hProcess, ((PMANUAL_INJECT)mem + 1), mem);

	if (!hThread)
	{
		//_cprintf("\nError: Unable to execute loader code (%d)\n", GetLastError());

		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);

		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &ExitCode);

	if (!ExitCode)
	{
		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);

		CloseHandle(hThread);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);

	CloseHandle(hProcess);

	// _cprintf("\nDLL injected at %#p\n", image);

	if (pINH->OptionalHeader.AddressOfEntryPoint)
	{
		//_cprintf("\nBase Entry Point: %#p\n", (PVOID)((LPBYTE)image + pINH->OptionalHeader.AddressOfEntryPoint));
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}