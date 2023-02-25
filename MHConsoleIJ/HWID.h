//#include <time.h>
//#include <vector>
//#include <iostream>
//#include <sstream>
//#include <fstream>
//#include <istream>
//#include <stdlib.h>
//#include <cstddef> 
//#include <algorithm>
//#pragma comment(lib, "ws2_32.lib")
//
////#define http /*https://mediahacker.net/hwidth/md5.php?MD5=%s*/XorStr<0x05,46,0x45C6545D>("\x6D\x72\x73\x78\x7A\x30\x24\x23\x60\x6B\x6B\x79\x70\x7A\x72\x77\x7E\x73\x65\x36\x77\x7F\x6F\x33\x75\x69\x76\x44\x55\x4A\x0C\x49\x41\x13\x09\x58\x41\x5A\x14\x61\x69\x1B\x12\x15\x42"+0x45C6545D).s
////#define Login /*https://mediahacker.net/loginproMH/infestationThailand/HWID.php*/XorStr<0x68,64,0x9EF3E990>("\x00\x1D\x1E\x1B\x1F\x57\x41\x40\x1D\x14\x16\x1A\x15\x1D\x17\x14\x13\x1C\x08\x55\x12\x18\x0A\x50\xEC\xEE\xE5\xEA\xEA\xF5\xF4\xE8\xC5\xC1\xA5\xE2\xE2\xEB\xEB\xFC\xE4\xF0\xE6\xFA\xFB\xFB\xC2\xFF\xF9\xF0\xF6\xFA\xF2\xF9\xB1\xD7\xF7\xE8\xE6\x8D\xD4\xCD\xD6"+0x9EF3E990).s
//#define http /*http://server-media.tk/hwidth/md5.php?MD5=%s*/XorStr<0x5E,45,0x5F85EAB7>("\x36\x2B\x14\x11\x58\x4C\x4B\x16\x03\x15\x1E\x0C\x18\x46\x01\x08\x0A\x06\x11\x5F\x06\x18\x5B\x1D\x01\x1E\x1C\x0D\x12\x54\x11\x19\x4B\x51\xF0\xE9\xF2\xBC\xC9\xC1\xB3\xBA\xAD\xFA"+0x5F85EAB7).s
//
////#define Login "http://www.server-media.tk/loginproMH/infestationThailand/WarZTH.php?hwid=%s"
////#define Login "http://www.server-media.tk/loginproMH/BullZ/BullZ.php?hwid=%s"
////#define Login "http://www.mediahacker.net/loginproMH/DreamZ/DreamZ.php?hwid=%s"
////#define Login "http://www.server-media.tk/loginproMH/CSGO/CSGO.php?hwid=%s"
////#define Login "http://www.server-media.tk/loginproMH/40Z/40Z.php?hwid=%s"
////#define Login "http://server-media.tk/loginproMH/17z/17z.php?hwid=%s"
////#define Login /*http://www.server-media.tk/loginproMH/44Z/44Z.php?hwid=%s*/XorStr<0x48,58,0x37B2D435>("\x20\x3D\x3E\x3B\x76\x62\x61\x38\x27\x26\x7C\x20\x31\x27\x20\x32\x2A\x74\x37\x3E\x38\x34\x3F\x71\x14\x0A\x4D\x0F\x0B\x02\x0F\x09\x18\x1B\x05\x26\x24\x42\x5A\x5B\x2A\x5E\x46\x47\x2E\x5B\x06\x1F\x08\x46\x12\x0C\x15\x19\x43\x5A\xF3"+0x37B2D435).s
////#define Login "http://www.server-media.tk/loginproMH/Takang/Takang.php?hwid=%s"
////#define Login "http://www.server-media.tk/loginproMH/MMZ/MMZ.php?hwid=%s" //66Z
////#define Login /*http://www.server-media.tk/loginproMH/MVPZ/MVPZ.php?hwid=%s*/XorStr<0xF9,60,0x4A6E1A98>("\x91\x8E\x8F\x8C\xC7\xD1\xD0\x77\x76\x75\x2D\x77\x60\x74\x71\x6D\x7B\x27\x66\x69\x69\x67\x6E\x3E\x65\x79\x3C\x78\x7A\x71\x7E\x76\x69\x68\x74\x51\x55\x31\x52\x76\x71\x78\x0C\x69\x73\x76\x7D\x06\x59\x42\x5B\x13\x45\x59\x46\x54\x0C\x17\x40"+0x4A6E1A98).s
////#define Login "http://www.server-media.tk/loginproMH/iFatZ/iFatZ.php?hwid=%s"
////#define Login "http://www.server-media.tk/loginproMH/2017z/2017z.php?hwid=%s"
////#define Login /*http://www.server-media.tk/loginproMH/FLZ/Flz.php?hwid=%s*/XorStr<0x30,58,0x3EBB104C>("\x58\x45\x46\x43\x0E\x1A\x19\x40\x4F\x4E\x14\x48\x59\x4F\x48\x5A\x32\x6C\x2F\x26\x20\x2C\x27\x69\x3C\x22\x65\x27\x23\x2A\x27\x21\x20\x23\x3D\x1E\x1C\x7A\x10\x1B\x02\x76\x1C\x37\x26\x73\x2E\x37\x10\x5E\x0A\x14\x0D\x01\x5B\x42\x1B"+0x3EBB104C).s
////#define Login "http://www.server-media.tk/loginproMH/ToyStoryZ/ToyStoryZ.php?hwid=%s"
//#define Login "http://www.server-media.tk/loginproMH/RaycityZ/RaycityZ.php?hwid=%s"
////#define Login "http://www.server-media.tk/loginproMH/NGANZ/NGANZ.php?hwid=%s"
////#define Login "http://www.server-media.tk/loginproMH/WarZS/WarZS.php?hwid=%s"
////#define Login "http://www.server-media.tk/loginproMH/ALLNEWZ/ALLNEWZ.php?hwid=%s"
////#define Login "http://www.server-media.tk/loginproMH/BabyZ/BabyZ.php?hwid=%s"
////#define Login "http://www.server-media.tk/loginproMH/PlaySurvivalZ/PlaySurvivalZ.php?hwid=%s"
////#define Login "http://www.server-media.tk/loginproMH/MMOTH/MMOTH.php?hwid=%s"
////#define Login "http://www.server-media.tk/loginproMH/Z4/Z4.php?hwid=%s"
//#define BUFFERSIZE 1
//
//BOOL HWInfos();
//int HCheck = 0;
//
//int validHWID(char* hwid, string request);
//void die_with_error(char *errorMessage);
//void die_with_wserror(char *errorMessage);
//char hwid[MAX_PATH] = "";
//
//void SystemLetter(TCHAR *vol) {
//	TCHAR buffer[30];
//	GetSystemWindowsDirectory(buffer, 30);
//	for (int i = 0; i < 2; i++)
//		vol[i] = buffer[i];
//	vol[2] = 0;
//}
//
//string ID() {
//	TCHAR vol[3];
//	SystemLetter(vol);
//	string letter = string(vol) + "\\";
//	string ss;
//	ss = "Err_StringIsNull";
//	UCHAR szFileSys[255],
//		szVolNameBuff[255];
//	char lpszComputer[255];
//	DWORD dComputer = sizeof(lpszComputer);
//	DWORD dwSerial;
//	DWORD dwMFL;
//	DWORD dwSysFlags;
//	int error = 0;
//	BOOL success = GetVolumeInformationA(LPCTSTR(letter.c_str()), (LPTSTR)szVolNameBuff,
//		255, &dwSerial,
//		&dwMFL, &dwSysFlags,
//		(LPTSTR)szFileSys,
//		255);
//	BOOL success2 = GetComputerName(lpszComputer, &dComputer);
//	//char hash[9999];
//	//sprintf_s(hash, "%s",lpszComputer);
//	//MessageBox(NULL, hash, "ข้อความจากระบบ", MB_OK | MB_ICONSTOP);
//
//	if (!success2) {
//		ss = "Err_Not_Elevated_Computer";
//	}
//	if (!success) {
//		ss = "Err_Not_Elevated";
//	}
//	std::stringstream errorStream;
//	errorStream << dwSerial << lpszComputer;
//	return string(errorStream.str().c_str());
//}
//
////==============================================================//
//
//// Connect HTTP hwid
//
//int validHWID(char* hwid, string request) {
//	char length2[100];
//	_itoa(strlen(hwid), length2, 10);
//
//	string response;
//	int resp_leng;
//	char buffer[BUFFERSIZE];
//	struct sockaddr_in serveraddr;
//	int sock;
//
//	WSADATA wsaData;
//	//==============================================================//
//	char *ipaddress = "45.64.184.214"; // ไอพี // เว็บ mediahacker 103.233.193.42  www.puntersindo.pe.hu HWIDSS.php 31.170.164.212
//
//	int port = 80; // port
//
//	/*request += "GET //loginproMH/infestationThailand/HWID.php HTTP/1.0\r\n"; //ที่อยู่ไฟล์
//
//	request += "Host: www.mediahacker.net\r\n"; //เว็บ
//	request += "\r\n";
//	//==============================================================//
//	request += "\r\n";*/
//	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
//		die_with_wserror("WSAStartup() failed");
//
//	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
//		die_with_wserror("socket() failed");
//
//	memset(&serveraddr, 0, sizeof(serveraddr));
//	serveraddr.sin_family = AF_INET;
//	serveraddr.sin_addr.s_addr = inet_addr(ipaddress);
//	serveraddr.sin_port = htons((unsigned short)port);
//	if (connect(sock, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
//		die_with_wserror("connect() failed");
//	if (send(sock, request.c_str(), request.length(), 0) != request.length())
//		die_with_wserror("send() sent a different number of bytes than expected");
//
//	response = "";
//	resp_leng = BUFFERSIZE;
//	while (resp_leng == BUFFERSIZE)
//	{
//		resp_leng = recv(sock, (char*)&buffer, BUFFERSIZE, 0);
//		if (resp_leng>0)
//			response += string(buffer).substr(0, resp_leng);
//	}
//
//	char str2[] = "\n";
//	char * pnt;
//	char myvalue[100];
//	char myvalue2[100];
//	pnt = strtok((char *)response.c_str(), str2);
//
//	while (pnt != NULL)
//	{
//
//
//		std::string my_string(pnt);
//		my_string = my_string.substr(0, 32);
//		char length1[100];
//		_itoa(strlen(my_string.c_str()), length1, 10);
//		if (strcmp(my_string.c_str(), hwid) == 0) {
//
//			closesocket(sock);
//			WSACleanup();
//			return 1;
//		}
//		pnt = strtok(NULL, str2);
//	}
//	closesocket(sock);
//	WSACleanup();
//	return 0;
//}
//
////==============================================================//
//
////ตรวจสอบ HWID
///*BOOL BaseHWID()
//{
//char hash[9999];
//
//string request = "GET //loginproMH/infestationThailand/HWID.php HTTP/1.0\r\n"; //ที่อยู่ไฟล์
//request += "Host: www.mediahacker.net\r\n"; //เว็บ
//request += "\r\n";
//request += "\r\n";
//
//string requestHTTP;// = "https://mediahacker.net";
//requestHTTP += "/hwidth/md5.php?MD5=%s"; //เว็บ
//
//sprintf_s(hash, requestHTTP.c_str(), ID().c_str());
//
//MAKEURLPAGE(hash, buffer5, len);
//
//if (validHWID(buffer5, request.c_str()) == 1)
//{
//HCheck = 1;
//}
//else
//{
//HCheck = 0;
//ExitProcess(1);
//Sleep(1);
//}
//return 0;
//}*/
//
//BOOL BaseHWID()
//{
//	/*char GuidTechUrl[9999];
//	char hash[9999];
//	string FinalID = ID();
//	//string request = "GET //loginproMH/infestationThailand/HWID.php HTTP/1.0\r\n"; //ที่อยู่ไฟล์
//	//string request = "GET //loginproMH/CSGO/HWID.php HTTP/1.0\r\n"; //ที่อยู่ไฟล์
//	//string request = "GET //loginproMH/BullZ/HWID.php HTTP/1.0\r\n"; //ที่อยู่ไฟล์
//	//string request = "GET //loginproMH/DreamZ/HWID.php HTTP/1.0\r\n"; //ที่อยู่ไฟล์
//	string request = "GET //loginproMH/44Z/HWID.php HTTP/1.0\r\n"; //ที่อยู่ไฟล์
//
//	sprintf_s(hash, http, ID().c_str());
//
//	if (GETURLPAGE(hash, buffer5, len) != 0)
//	{
//	request += "Host: www.mediahacker.net\r\n"; //เว็บ
//	request += "\r\n";
//	request += "\r\n";
//
//	if (validHWID(buffer5, request.c_str()) == 1)
//	{
//	HCheck = 1;
//	}
//	else
//	{
//	HCheck = 0;
//	MessageBox(0,"เลขเครืองไม่ตรงกับระบบ หรือ โปรหมดเวลา","System",MB_ICONERROR);
//	ExitProcess(1);
//	Sleep(1);
//	}
//	}
//	*/
//	char GuidTechUrl[9999];
//	char hash[9999];
//	string FinalID = ID();
//
//	sprintf_s(hash, http, FinalID.c_str());
//
//	if (GETURLPAGE(hash, buffer5, len) != 0)
//		sprintf_s(GuidTechUrl, Login, buffer5);
//	if (GETURLPAGE(GuidTechUrl, VC, len) != 0)
//		if (strcmp(VC, /*GuidVerified*/XorStr<0x4D, 13, 0xADDA1ABF>("\x0A\x3B\x26\x34\x07\x37\x21\x3D\x33\x3F\x32\x3C" + 0xADDA1ABF).s) == 0)
//		{
//			HCheck = 1;
//		}
//		else if (strcmp(VC, /*KUY*/XorStr<0xC2, 4, 0x1A474291>("\x89\x96\x9D" + 0x1A474291).s) == 0)
//		{
//			HCheck = 0;
//			MessageBox(0, "ไม่สามารถตรวจสอบเลขเครืองได้", "พบปัญหา", 0);
//		}
//		else if (strcmp(VC, /*Username and Password Incorrect!*/XorStr<0x91, 33, 0xC24F99F3>("\xC4\xE1\xF6\xE6\xFB\xF7\xFA\xFD\xB9\xFB\xF5\xF8\xBD\xCE\xFE\xD3\xD2\xD5\xCC\xD6\xC1\x86\xEE\xC6\xCA\xC5\xD9\xDE\xC8\xCD\xDB\x91" + 0xC24F99F3).s) == 0)
//		{
//			HCheck = 0;
//			MessageBox(0, "ไม่สามารถตรวจสอบเลขเครืองได้", "พบปัญหา", 0);
//		}
//		return 0;
//}
//
//
//void die_with_error(char *errorMessage)
//{
//	cerr << errorMessage << endl;
//	exit(1);
//}
//
//void die_with_wserror(char *errorMessage)
//{
//	cerr << errorMessage << ": " << WSAGetLastError() << endl;
//	exit(1);
//}
//
//#define BUFFER 8192
//static bool CreateKey()
//{
//	HKEY hKey;
//	int hr;
//	char value[255];
//	DWORD BufferSize = BUFFER;
//	//////////////pubg
//
//	//hr = RegCreateKeyEx(HKEY_CURRENT_USER,
//	//	/*Software\\MediaHacker\\Playerunknown*/XorStr<0xCB, 35, 0x083BC798>("\x98\xA3\xAB\xBA\xB8\xB1\xA3\xB7\x8F\x99\xB0\xB2\xBE\xB9\x91\xBB\xB8\xB7\xB8\xAC\x83\xB0\x8D\x83\x9A\x81\x97\x93\x89\x83\x87\x85\x9C\x82" + 0x083BC798).s,
//	//	0,
//	//	NULL,
//	//	REG_OPTION_NON_VOLATILE,
//	//	KEY_ALL_ACCESS,
//	//	NULL,
//	//	&hKey,
//	//	NULL);
//
//	//if (hr != ERROR_SUCCESS)
//	//	return false;
//
//	//hr = RegSetValueExA(hKey, /*1*/XorStr<0xCB, 2, 0x577F07AB>("\xFA" + 0x577F07AB).s, NULL, REG_SZ, (BYTE*)/*battlegrounds*/XorStr<0x1F, 14, 0x00984075>("\x7D\x41\x55\x56\x4F\x41\x42\x54\x48\x5D\x47\x4E\x58" + 0x00984075).s, strlen(/*battlegrounds*/XorStr<0x1F, 14, 0x00984075>("\x7D\x41\x55\x56\x4F\x41\x42\x54\x48\x5D\x47\x4E\x58" + 0x00984075).s) + 1);
//	//if (hr != ERROR_SUCCESS)
//	//	return false;
//
//	///////////////newz
//	hr = RegCreateKeyEx(HKEY_CURRENT_USER,
//		/*Software\\MediaHacker\\TheNewZ*/XorStr<0x07, 29, 0x243FF513>("\x54\x67\x6F\x7E\x7C\x6D\x7F\x6B\x53\x5D\x74\x76\x7A\x75\x5D\x77\x74\x73\x7C\x68\x47\x48\x75\x7B\x51\x45\x56\x78" + 0x243FF513).s,
//		0,
//		NULL,
//		REG_OPTION_NON_VOLATILE,
//		KEY_ALL_ACCESS,
//		NULL,
//		&hKey,
//		NULL);
//
//	if (hr != ERROR_SUCCESS)
//		return false;
//
//	hr = RegSetValueExA(hKey, /*1*/XorStr<0xCB, 2, 0x577F07AB>("\xFA" + 0x577F07AB).s, NULL, REG_SZ, (BYTE*)/*grounds*/XorStr<0x30, 8, 0xB9BA0F5D>("\x57\x43\x5D\x46\x5A\x51\x45" + 0xB9BA0F5D).s, strlen(/*grounds*/XorStr<0x30, 8, 0xB9BA0F5D>("\x57\x43\x5D\x46\x5A\x51\x45" + 0xB9BA0F5D).s) + 1);
//	if (hr != ERROR_SUCCESS)
//		return false;
//
//
//	//RegQueryValueExA(hKey, /*1*/XorStr<0xCB, 2, 0x577F07AB>("\xFA" + 0x577F07AB).s, NULL REG_SZ, NULL, (BYTE*)&value, &BufferSize);
//	/*RegGetValue(HKEY_CURRENT_USER, "Software\\MediaHacker\\WarZCheck", "1", RRF_RT_ANY, NULL, (PVOID)&value, &BufferSize);
//	if (strcmp(value, "TheNewZ") == 0)
//	{
//	MessageBox(0, "Read", "", 0);
//	}*/
//	//RegDeleteValue(hKey, (LPCSTR)"1");
//	RegCloseKey(hKey);
//	return true;
//}