//
//typedef struct _CLIENT_ID2
//{
//	PVOID UniqueProcess;
//	PVOID UniqueThread;
//}CLIENT_ID2, *PCLIENT_ID22;
//
//EXTERN_C NTSTATUS NTAPI RtlCreateUserThread(
//	HANDLE,
//	PSECURITY_DESCRIPTOR,
//	BOOLEAN,
//	ULONG,
//	PULONG,
//	PULONG,
//	PVOID,
//	PVOID,
//	PHANDLE,
//	PCLIENT_ID22);
//
//EXTERN_C PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID);
//EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
//EXTERN_C NTSTATUS NTAPI NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID22);
//EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
//
//
//typedef struct {
//	unsigned long dwAddress;
//} MBypass1;
//MBypass1 mbypass1[] =
//{
//	{ 0x00271B50 } //44z
//};


typedef struct {
	unsigned long dwAddress;
	unsigned char pBytes[8];
} MDump1;
MDump1 mDumps1[] =
{
		/*{ 0x003F3C52, { 0xE8, 0x0A, 0x08, 0x01, 0x00, 0xE9, 0x78, 0xFE } }*/
		
		//INFI/*{ 0x00403142, { 0xE8, 0xDB, 0x1D, 0x01, 0x00, 0xE9, 0x78, 0xFE } }*/
	
	//{ 0x0040A182, { 0xE8, 0x1B, 0x1B, 0x01, 0x00, 0xE9, 0x78, 0xFE } } Work
		
		//{ 0x00408AC2, { 0xE8, 0x3A, 0x18, 0x01, 0x00, 0xE9, 0x78, 0xFE } }  66Z

	{ 0x0040A182, { 0xE8, 0x1B, 0x1B, 0x01, 0x00, 0xE9, 0x78, 0xFE } }
};
// E8 07 87 73 00 F9 8D 80   E8 2D 09 01 00 E9 78 FE FF  E8 2D 09 01 00 E9 78 FE
// 
// 
//HMODULE    module;
DWORD_PTR GetProcessBaseAddress(DWORD processID)
{
	DWORD_PTR   baseAddress = 0;
	//HANDLE      processHandle;
	HANDLE      processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	HMODULE     *moduleArray;
	LPBYTE      moduleArrayBytes;
	DWORD       bytesRequired;
	/*NTSTATUS status;

	OBJECT_ATTRIBUTES oa;
	CLIENT_ID2 cid;

	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

	cid.UniqueProcess = (HANDLE)processID;
	cid.UniqueThread = 0;

	NtOpenProcess(&processHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &oa, &cid);*/

	if (processHandle)
	{
		if (EnumProcessModules(processHandle, NULL, 0, &bytesRequired))
		{
			if (bytesRequired)
			{
				moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);

				if (moduleArrayBytes)
				{
					unsigned int moduleCount;

					moduleCount = bytesRequired / sizeof(HMODULE);
					moduleArray = (HMODULE *)moduleArrayBytes;

					if (EnumProcessModules(processHandle, moduleArray, bytesRequired, &bytesRequired))
					{
						baseAddress = (DWORD_PTR)moduleArray[0];
					//	module = moduleArray[0];
					}

					LocalFree(moduleArrayBytes);
				}
			}
		}

		CloseHandle(processHandle);
	}

	return baseAddress;
}
DWORD DumpScanV1()
{
	bool bReturn = false;

	HANDLE hProc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	DWORD dwGetProcessID = 0;


	if (hProc != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 mP32;

		mP32.dwSize = sizeof(mP32);

		Process32First(hProc, &mP32);

		do {
		

			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, mP32.th32ProcessID);
			if (hProcess != NULL)
			{
				for (int i = 0; i < (sizeof(mDumps1) / sizeof(MDump1)); i++)
				{
					unsigned char pBytes[8];
					unsigned long pBytesRead;
					SIZE_T*f;

					DWORD BaseAddress = GetProcessBaseAddress(mP32.th32ProcessID);


					DWORD Offset = BaseAddress + mDumps1[i].dwAddress;

					if (ReadProcessMemory(hProcess, (void*)Offset, (LPVOID)pBytes, 8, &pBytesRead))
					{
						if (pBytesRead == 8)
						{
							if (!memcmp(pBytes, mDumps1[i].pBytes, 8))
							{
								dwGetProcessID = (DWORD)mP32.th32ProcessID;
							}
						}
					}
				}
		
			}
		} while (Process32Next(hProc, &mP32));
	}





	return dwGetProcessID;
}

