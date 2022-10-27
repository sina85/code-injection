#include <Windows.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef struct {
	int data;
} ARGUMENTS, *PARGUMENTS;

DWORD WINAPI Injectable(PVOID p) {
	ARGUMENTS *args = (ARGUMENTS*)p;
	// this is the code that will be run by the thread
	printf("This is a test.");
	getchar();
	return 12;
}
DWORD WINAPI InjectableEnd() { return 0; }

void main(){
	int c{};
	HANDLE handle = NULL, snapshot;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	Process32First(snapshot, &pe32);
	
	while (true) {
		if (strcmp(pe32.szExeFile, "explorer.exe"))
			handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (!Process32Next(snapshot, &pe32)) break;
	}

	ARGUMENTS args;
	args.data = 101;

	PVOID arguments_address = VirtualAllocEx(handle, NULL, sizeof(ARGUMENTS), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(handle, (PVOID)arguments_address, &args, sizeof(ARGUMENTS), NULL);

	PVOID code_address = VirtualAllocEx(handle, NULL, (DWORD)InjectableEnd - (DWORD)Injectable, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(handle, (PVOID)code_address, Injectable, (DWORD)InjectableEnd - (DWORD)Injectable, NULL);
	HANDLE hThread;
	hThread = CreateRemoteThread(handle, NULL, 0, (LPTHREAD_START_ROUTINE)code_address, arguments_address, 0, NULL);

	CloseHandle(handle);
	CloseHandle(snapshot);
}