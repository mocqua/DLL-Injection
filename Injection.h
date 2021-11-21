#pragma once
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlHelp32.h>


THREADENTRY32 te32;
DWORD processID;
BOOL CreateRemoteThread1(char* dllPath, HANDLE processHandle);
BOOL NtCreateThreadEx2(char* dllPath, HANDLE processHandle);
BOOL SetWindowsHookEx3(char* dllPath, DWORD processId);
BOOL RtlCreatUserThread4(char* dllPath, HANDLE processHandle);
BOOL QueueUserAPC5(char* dllPath, HANDLE processHandle, DWORD processId);
BOOL CreateRemoteThread_Re(char* dllPath, HANDLE hProcess);
struct NtCreateThreadExBuffer
{
	SIZE_T	Size;
	SIZE_T	Unknown1;
	SIZE_T	Unknown2;
	PULONG	Unknown3;
	SIZE_T	Unknown4;
	SIZE_T	Unknown5;
	SIZE_T	Unknown6;
	PULONG	Unknown7;
	SIZE_T	Unknown8;
};

typedef NTSTATUS(WINAPI* lpNtCreateThreadEx)(
	OUT		PHANDLE				hThread,
	IN		ACCESS_MASK			DesiredAccess,
	IN		LPVOID				ObjectAttributes,
	IN		HANDLE				ProcessHandle,
	IN		LPVOID				lpStartAddress,
	IN		LPVOID				lpParameter,
	IN		ULONG				CreateSuspended,
	IN		SIZE_T				StackZeroBits,
	IN		SIZE_T				SizeOfStackCommit,
	IN		SIZE_T				SizeOfStackReserve,
	OUT		LPVOID				lpBytesBuffer
);
typedef DWORD(WINAPI* pRtlCreatUserThread)(

	IN		HANDLE					ProcessHandle,
	IN 		PSECURITY_DESCRIPTOR	SecurityDescriptor,
	IN		BOOLEAN					CreateSuspended,
	IN		ULONG					StackZeroBits,
	IN OUT	PULONG					StackReserved,
	IN OUT	PULONG					StackCommit,
	IN		PVOID					StartAddress,
	IN		PVOID					StartParameter,
	OUT		PHANDLE					ThreadHandle,
	OUT		PVOID					ClientID
);