#include "Patcher.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <exception>

#include "Win32Structure.hpp"
#include "TargetStub32.h"
#ifdef _WIN64
#include "TargetStub64.h"
#endif

typedef uint32_t (__stdcall *NtQueryInformationProcessType)(HANDLE ProcessHandle, int ProcessInformationClass, 
														PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

typedef uint32_t (__stdcall *NtAllocateVirtualMemoryType)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

NtQueryInformationProcessType NtQueryInformationProcess;
NtAllocateVirtualMemoryType NtAllocateVirtualMemory;

struct TargetData64
{
	//For >Windows 8
	uint64_t originalNtCreateFile;
	uint64_t originalNtDeviceIoControlFile;
	uint64_t originalNtWriteFile;
	uint64_t originalNtReadFile;
	uint64_t originalNtQueryVolumeInformationFile;
	uint64_t originalNtCreateUserProcess;
	uint64_t originalNtDuplicateObject;
	uint64_t originalNtClose;

	//Older windows
	uint64_t originalNtConnectPort;
	uint64_t originalNtSecureConnectPort;
	uint64_t originalNtRequestWaitReplyPort;
};

struct TargetData32
{
	//For >Windows 8
	uint32_t originalNtCreateFile;
	uint32_t originalNtDeviceIoControlFile;
	uint32_t originalNtWriteFile;
	uint32_t originalNtReadFile;
	uint32_t originalNtQueryVolumeInformationFile;
	uint32_t originalNtCreateUserProcess;
	uint32_t originalNtDuplicateObject;
	uint32_t originalNtClose;
	
	//Older windows
	uint32_t originalNtConnectPort;
	uint32_t originalNtSecureConnectPort;
	uint32_t originalNtRequestWaitReplyPort;
};

struct PatchData
{
	size_t ntdllBase;
	size_t syscallSize;

	size_t ntCreateFile;
	size_t ntWriteFile;
	size_t ntReadFile;
	size_t ntDeviceIoControlFile;
	size_t ntQueryVolumeInformationFile;
	size_t ntCreateUserProcess;
	size_t ntDuplicateObject;
	size_t ntClose;
	size_t ntConnectPort;
	size_t ntSecureConnectPort;
	size_t ntRequestWaitReplyPort;

	size_t HookedNtCreateFile;
	size_t HookedNtReadFile;
	size_t HookedNtWriteFile;
	size_t HookedNtDeviceIoControlFile;
	size_t HookedNtQueryVolumeInformationFile;
	size_t HookedNtCreateUserProcess;
	size_t HookedNtDuplicateObject;
	size_t HookedNtClose;
	size_t HookedNtConnectPort;
	size_t HookedNtSecureConnectPort;
	size_t HookedNtRequestWaitReplyPort;
};

PatchData patchData;

template<int WordSize>
void createTrampoline(uint8_t *dst, size_t functionAddr, size_t targetData)
{
	//pop return address from stack, push our data to first of the argument list, push again return address.
	if(WordSize == 4)
	{
		static uint8_t patch[] = {
			0x58, //pop eax
			0x68, 0x00, 0x00, 0x00, 0x00, //push data
			0x50, //push eax
			0x68, 0x00, 0x00, 0x00, 0x00, //push addr
			0xc3 //ret
		};
		*reinterpret_cast<uint32_t *>(&patch[2]) = static_cast<uint32_t>(targetData);
		*reinterpret_cast<uint32_t *>(&patch[8]) = static_cast<uint32_t>(functionAddr);

		memcpy(dst, patch, sizeof(patch));
	}
	else if(WordSize == 8)
	{
		static uint8_t patch[] = {																	//									 rcx: data, rdx: 1st arg
			0x58, //pop rax																			// rcx: 1st arg, rdx: 2nd arg 	     r8: 2nd arg, r9: 3rd arg
			0x6a, 0x00, //push 0 (home space 1)														// r8: 3rd arg, r9: 4th arg		     rsp-8  | <Return Address>
			0x4c, 0x89, 0x4c, 0x24, 0x20, //mov [rsp+32], r9										// rsp-8  | <Return Address>         rsp    | <home space 1>
			0x4d, 0x89, 0xc1, //mov r9, r8 (shift registers)										// rsp    | <home space 1>           rsp+8  | <home space 2>
			0x49, 0x89, 0xd0, //mov r8, rdx															// rsp+8  | <home space 2>		=>   rsp+16 | <home space 3>
			0x48, 0x89, 0xca, //mov rdx, rcx														// rsp+16 | <home space 3>		     rsp+24 | <home space 4>
			0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //movabs rcx, data			// rsp+24 | <home space 4>		     rsp+32 | <4th arg>
			0x48, 0x89, 0x05, 0x19, 0x00, 0x00, 0x00, //mov [rip+25], rax (save return address)		// rsp+32 | <5th arg>			     rsp+40 | <5th arg>
			0xff, 0x15, 0x0b, 0x00, 0x00, 0x00, //call [rip+11]										// rsp+40 | <6th arg>			     rsp+48 | <6th arg>
			0x48, 0x83, 0xc4, 0x08, //add rsp, 8(remove home space)
			0xff, 0x35, 0x09, 0x00, 0x00, 0x00, //push [rip+9] (restore return address)
			0xc3, //ret
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //functionAddr
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //data
		};		
		*reinterpret_cast<uint64_t *>(&patch[19]) = static_cast<uint64_t>(targetData);
		*reinterpret_cast<uint64_t *>(&patch[51]) = static_cast<uint64_t>(functionAddr);

		memcpy(dst, patch, sizeof(patch));
	}
}

void patchFunction(HANDLE processHandle, size_t dst, int32_t trampoline)
{
	uint8_t buf[6] = {0x68, 0x00, 0x00, 0x00, 0x00, 0xc3}; //push addr; ret
	*reinterpret_cast<int32_t *>(&buf[1]) = trampoline;

	//writeprocessmemory succeeds regardless of memory protection.
	WriteProcessMemory(processHandle, reinterpret_cast<LPVOID>(dst), buf, 6, nullptr);
}

template<typename WordType>
WordType addHook(HANDLE processHandle, uint8_t *trampolineBase, size_t newFunction, size_t originalFunction,
				 size_t originalFunctionSize, void *targetTargetData, uint8_t *targetTrampolineBase, size_t offset)
{
	WordType originalAddress = reinterpret_cast<WordType>(targetTrampolineBase + offset);
	ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(originalFunction), reinterpret_cast<LPVOID>(trampolineBase + offset), originalFunctionSize, nullptr);
	offset += originalFunctionSize + 1;

	createTrampoline<sizeof(WordType)>(trampolineBase + offset, newFunction, reinterpret_cast<size_t>(targetTargetData));
	patchFunction(processHandle, originalFunction, reinterpret_cast<int32_t>(targetTrampolineBase + offset));

	return originalAddress;
}

template<typename TargetDataType>
void patch(HANDLE processHandle, PatchData *patchData, uint8_t *targetCodeBase)
{
	TargetDataType targetData;

	uint8_t *targetTrampolineData = nullptr;
	void *targetTargetData = VirtualAllocEx(processHandle, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	const size_t trampolineSize = 1500;

	size_t zeroBits = 0;
#ifdef _WIN64
	zeroBits = 0x7ffe0000; //amd64 undocumented trick: larger zerobit act as a address mask.
#endif
	size_t size = 0x1000;
	NtAllocateVirtualMemory(processHandle, reinterpret_cast<PVOID *>(&targetTrampolineData), zeroBits, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 

	uint8_t *trampolineData = new uint8_t[trampolineSize];
	ZeroMemory(trampolineData, trampolineSize);

	targetData.originalNtCreateFile = addHook<decltype(targetData.originalNtCreateFile)>
		(processHandle, trampolineData, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtCreateFile),
		patchData->ntCreateFile, patchData->syscallSize, targetTargetData, targetTrampolineData, 0);

	targetData.originalNtReadFile = addHook<decltype(targetData.originalNtReadFile)>
		(processHandle, trampolineData, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtReadFile),
		patchData->ntReadFile, patchData->syscallSize, targetTargetData, targetTrampolineData, 100);

	targetData.originalNtWriteFile = addHook<decltype(targetData.originalNtWriteFile)>
		(processHandle, trampolineData, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtWriteFile),
		patchData->ntWriteFile, patchData->syscallSize, targetTargetData, targetTrampolineData, 200);

	targetData.originalNtDeviceIoControlFile = addHook<decltype(targetData.originalNtDeviceIoControlFile)>
		(processHandle, trampolineData, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtDeviceIoControlFile),
		patchData->ntDeviceIoControlFile, patchData->syscallSize, targetTargetData, targetTrampolineData, 300);

	targetData.originalNtQueryVolumeInformationFile = addHook<decltype(targetData.originalNtQueryVolumeInformationFile)>
		(processHandle, trampolineData, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtQueryVolumeInformationFile),
		patchData->ntQueryVolumeInformationFile, patchData->syscallSize, targetTargetData, targetTrampolineData, 400);

	targetData.originalNtCreateUserProcess = addHook<decltype(targetData.originalNtCreateUserProcess)>
		(processHandle, trampolineData, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtCreateUserProcess),
		patchData->ntCreateUserProcess, patchData->syscallSize, targetTargetData, targetTrampolineData, 500);
	
	targetData.originalNtDuplicateObject = addHook<decltype(targetData.originalNtDuplicateObject)>
		(processHandle, trampolineData, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtDuplicateObject),
		patchData->ntDuplicateObject, patchData->syscallSize, targetTargetData, targetTrampolineData, 600);

	targetData.originalNtClose = addHook<decltype(targetData.originalNtClose)>
		(processHandle, trampolineData, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtClose),
		patchData->ntClose, patchData->syscallSize, targetTargetData, targetTrampolineData, 700);

	targetData.originalNtConnectPort = addHook<decltype(targetData.originalNtConnectPort)>
		(processHandle, trampolineData, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtConnectPort),
		patchData->ntConnectPort, patchData->syscallSize, targetTargetData, targetTrampolineData, 800);

	targetData.originalNtSecureConnectPort = addHook<decltype(targetData.originalNtSecureConnectPort)>
		(processHandle, trampolineData, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtSecureConnectPort),
		patchData->ntSecureConnectPort, patchData->syscallSize, targetTargetData, targetTrampolineData, 900);

	targetData.originalNtRequestWaitReplyPort = addHook<decltype(targetData.originalNtRequestWaitReplyPort)>
		(processHandle, trampolineData, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtRequestWaitReplyPort),
		patchData->ntRequestWaitReplyPort, patchData->syscallSize, targetTargetData, targetTrampolineData, 1000);

	WriteProcessMemory(processHandle, targetTargetData, &targetData, sizeof(targetData), nullptr);
	WriteProcessMemory(processHandle, targetTrampolineData, trampolineData, trampolineSize, nullptr);

	delete [] trampolineData;
}

bool Patcher::patchProcess(void *processHandle)
{
	//check subsystem
	PROCESS_BASIC_INFORMATION pbi;
	NtQueryInformationProcess(processHandle, 0, &pbi, sizeof(pbi), nullptr);
	uint8_t header[0x1000];
#ifdef _WIN64
	PEB64 peb;
#else
	PEB32 peb;
#endif
	ReadProcessMemory(processHandle, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr);
	ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(peb.ImageBaseAddress), header, sizeof(header), nullptr);
	IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(header);
	IMAGE_NT_HEADERS *ntHeader = reinterpret_cast<IMAGE_NT_HEADERS *>(header + dosHeader->e_lfanew);
	if(ntHeader->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI)
		return false;

	uint8_t *targetCodeBase = reinterpret_cast<uint8_t *>(VirtualAllocEx(processHandle, nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ));
#ifdef _WIN64
	if(!WriteProcessMemory(processHandle, targetCodeBase, reinterpret_cast<LPCVOID>(stubData64), sizeof(stubData64), nullptr))
		throw std::exception("WriteProcessMemory failed");
	patch<TargetData64>(processHandle, &patchData, targetCodeBase);
#else
	if(!WriteProcessMemory(processHandle, targetCodeBase, reinterpret_cast<LPCVOID>(stubData32), sizeof(stubData32), nullptr))
		throw std::exception("WriteProcessMemory failed");
	patch<TargetData32>(processHandle, &patchData, targetCodeBase);
#endif
	return true;
}

void Patcher::initPatch()
{
	HMODULE ntdllBase = GetModuleHandle(L"ntdll.dll");
	patchData.ntdllBase = reinterpret_cast<size_t>(ntdllBase);
	patchData.ntCreateFile = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtCreateFile"));
	patchData.ntWriteFile = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtWriteFile"));
	patchData.ntReadFile = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtReadFile"));
	patchData.ntDeviceIoControlFile = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtDeviceIoControlFile"));
	patchData.ntQueryVolumeInformationFile = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtQueryVolumeInformationFile"));
	patchData.ntCreateUserProcess = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtCreateUserProcess"));
	patchData.ntDuplicateObject = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtDuplicateObject"));
	patchData.ntClose = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtClose"));
	patchData.ntConnectPort = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtConnectPort"));
	patchData.ntSecureConnectPort = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtSecureConnectPort"));
	patchData.ntRequestWaitReplyPort = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtRequestWaitReplyPort"));

	NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessType>(GetProcAddress(ntdllBase, "NtQueryInformationProcess"));
	NtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemoryType>(GetProcAddress(ntdllBase, "NtAllocateVirtualMemory"));
#ifdef _WIN64
	patchData.syscallSize = 11; //mov r10, rcx; mov eax, <syscallno>; syscall; retn
	patchData.HookedNtCreateFile = HookedNtCreateFileAddr64;
	patchData.HookedNtReadFile = HookedNtReadFileAddr64;
	patchData.HookedNtWriteFile = HookedNtWriteFileAddr64;
	patchData.HookedNtDeviceIoControlFile = HookedNtDeviceIoControlFileAddr64;
	patchData.HookedNtQueryVolumeInformationFile = HookedNtQueryVolumeInformationFileAddr64;
	patchData.HookedNtCreateUserProcess = HookedNtCreateUserProcessAddr64;
	patchData.HookedNtDuplicateObject = HookedNtDuplicateObjectAddr64;
	patchData.HookedNtClose = HookedNtCloseAddr64;
	patchData.HookedNtConnectPort = HookedNtConnectPortAddr64;
	patchData.HookedNtSecureConnectPort = HookedNtSecureConnectPortAddr64;
	patchData.HookedNtRequestWaitReplyPort = HookedNtRequestWaitReplyPortAddr64;
#else
	patchData.syscallSize = 15; //mov eax, <syscallno>; call dword ptr fs:[0xc0]; retn 0xnn; (wow64)
								//mov eax, <syscallno>; mov edx, 0x7ffe0300; call [edx]; retn 0xnn;
	patchData.HookedNtCreateFile = HookedNtCreateFileAddr32;
	patchData.HookedNtReadFile = HookedNtReadFileAddr32;
	patchData.HookedNtWriteFile = HookedNtWriteFileAddr32;
	patchData.HookedNtDeviceIoControlFile = HookedNtDeviceIoControlFileAddr32;
	patchData.HookedNtQueryVolumeInformationFile = HookedNtQueryVolumeInformationFileAddr32;
	patchData.HookedNtCreateUserProcess = HookedNtCreateUserProcessAddr32;
	patchData.HookedNtDuplicateObject = HookedNtDuplicateObjectAddr32;
	patchData.HookedNtClose = HookedNtCloseAddr32;
	patchData.HookedNtConnectPort = HookedNtConnectPortAddr32;
	patchData.HookedNtSecureConnectPort = HookedNtSecureConnectPortAddr32;
	patchData.HookedNtRequestWaitReplyPort = HookedNtRequestWaitReplyPortAddr32;
#endif
}
