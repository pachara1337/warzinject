#include "Xorstr.h"

#define UserAgent /*UserAgent*/XorStr<0xA1,10,0xC90993FD>("\xF4\xD1\xC6\xD6\xE4\xC1\xC2\xC6\xDD"+0xC90993FD).s
char buffer5[9999];
int len = 32;
char VC[9999];

BOOL GETURLPAGE(char *link, char *buffer, int maxsize)
{
	HINTERNET hSession;
	HINTERNET hURL;
	DWORD dwBYTEsRead;
	int ok = 0;

	buffer[0] = 0;
	hSession = InternetOpen(                         // Make internet connection.
		UserAgent,					   // agent
		INTERNET_OPEN_TYPE_PRECONFIG,    // access
		NULL, NULL, 0);                  // defaults

	if (hSession)
	{
		hURL = InternetOpenUrlA(  // Make connection to desired page.
			hSession,                        // session handle
			link,                             // URL to access
			NULL, 0, 0, 0);                 // defaults
		if (hURL)
		{
			// Read page into memory buffer.
			InternetReadFile(
				hURL,                // handle to URL
				(LPSTR)buffer,       // pointer to buffer
				(DWORD)maxsize,      // size of buffer
				&dwBYTEsRead);       // pointer to var to hold return value

			// Close down connections.
			//InternetCloseHandle(hURL);
			buffer[dwBYTEsRead] = 0;     // end string
			ok = (int)dwBYTEsRead;

		}
		else
		{
			MessageBox(0, "Downing Servcer", "", 0);
		}
		InternetCloseHandle(hSession);
	}
	return ok;
}