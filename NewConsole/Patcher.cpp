#include "Patcher.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <exception>

#include "TargetStub32.h"
#ifdef _WIN64
#include "TargetStub64.h"
#endif

struct TargetData64
{
	uint64_t originalNtCreateFile;
	uint64_t originalNtDeviceIoControlFile;
	uint64_t originalNtWriteFile;
	uint64_t originalNtReadFile;
};

struct TargetData32
{
	uint32_t originalNtCreateFile;
	uint32_t originalNtDeviceIoControlFile;
	uint32_t originalNtWriteFile;
	uint32_t originalNtReadFile;
};

struct PatchData
{
	size_t ntdllBase;

	size_t ntCreateFile;
	size_t ntWriteFile;
	size_t ntReadFile;
	size_t ntDeviceIoControlFile;

	size_t syscallSize;

	size_t HookedNtCreateFile;
	size_t HookedNtReadFile;
	size_t HookedNtWriteFile;
	size_t HookedNtDeviceIoControlFile;
};

PatchData patchData;
#ifdef _WIN64
PatchData patchDataWoW64;
#endif

template<int WordSize>
void createTrampoline(uint8_t *dst, size_t functionAddr, size_t targetData)
{
	//pop return address from stack, push our data to first of the argument list, push again return address.
	if(WordSize == 4)
	{
		uint8_t patch[] = {
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
		uint8_t patch[] = {																			// rcx: data, rdx: 1st arg
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

void patchFunction(HANDLE processHandle, size_t dst, size_t trampoline)
{
	int32_t rel = static_cast<int32_t>(trampoline) - (static_cast<int32_t>(dst) + 5);

	uint8_t buf[5] = {0xe9, };
	*reinterpret_cast<int32_t *>(&buf[1]) = rel; //jmp rel32

	//writeprocessmemory succeeds regardless of memory protection.
	WriteProcessMemory(processHandle, reinterpret_cast<LPVOID>(dst), buf, 5, nullptr);
}

template<typename TargetDataType>
void patch(HANDLE processHandle, PatchData *patchData, uint8_t *targetCodeBase)
{
	TargetDataType targetData;

	const size_t originalCodeSize = (patchData->syscallSize + 1) * 4;
	uint8_t *originalCode = new uint8_t[originalCodeSize];
	ZeroMemory(originalCode, originalCodeSize);
	//backup original functions.
	ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(patchData->ntCreateFile), 
					  reinterpret_cast<LPVOID>(originalCode), patchData->syscallSize, nullptr);
	ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(patchData->ntReadFile), 
					  reinterpret_cast<LPVOID>(originalCode + patchData->syscallSize + 1), patchData->syscallSize, nullptr);
	ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(patchData->ntWriteFile), 
					  reinterpret_cast<LPVOID>(originalCode + (patchData->syscallSize + 1) * 2), patchData->syscallSize, nullptr);
	ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(patchData->ntDeviceIoControlFile), 
					  reinterpret_cast<LPVOID>(originalCode + (patchData->syscallSize + 1) * 3), patchData->syscallSize, nullptr);

	uint8_t *targetOriginalCode = reinterpret_cast<uint8_t *>(VirtualAllocEx(processHandle, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ));
	WriteProcessMemory(processHandle, targetOriginalCode, originalCode, 100, nullptr);

	targetData.originalNtCreateFile = reinterpret_cast<decltype(TargetDataType::originalNtCreateFile)>(targetOriginalCode);
	targetData.originalNtReadFile = reinterpret_cast<decltype(TargetDataType::originalNtReadFile)>(targetOriginalCode + patchData->syscallSize + 1);
	targetData.originalNtWriteFile = reinterpret_cast<decltype(TargetDataType::originalNtWriteFile)>(targetOriginalCode + (patchData->syscallSize + 1) * 2);
	targetData.originalNtDeviceIoControlFile = reinterpret_cast<decltype(TargetDataType::originalNtDeviceIoControlFile)>(targetOriginalCode + (patchData->syscallSize + 1) * 3);

	void *targetTargetData = VirtualAllocEx(processHandle, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(processHandle, targetTargetData, &targetData, sizeof(targetData), nullptr);

	const size_t trampolineSize = 500;
	uint8_t *trampolineData = new uint8_t[trampolineSize];
	ZeroMemory(trampolineData, trampolineSize);
	createTrampoline<sizeof(decltype(TargetDataType::originalNtCreateFile))>
		(trampolineData, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtCreateFile), reinterpret_cast<size_t>(targetTargetData));
	createTrampoline<sizeof(decltype(TargetDataType::originalNtReadFile))>
		(trampolineData + 100, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtReadFile), reinterpret_cast<size_t>(targetTargetData));
	createTrampoline<sizeof(decltype(TargetDataType::originalNtWriteFile))>
		(trampolineData + 200, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtWriteFile), reinterpret_cast<size_t>(targetTargetData));
	createTrampoline<sizeof(decltype(TargetDataType::originalNtDeviceIoControlFile))>
		(trampolineData + 300, reinterpret_cast<size_t>(targetCodeBase + patchData->HookedNtDeviceIoControlFile), reinterpret_cast<size_t>(targetTargetData));

	uint8_t *targetTrampolineData = nullptr;
	size_t address = patchData->ntdllBase + 0x100000;
	while(true)
	{
		//try to allocate trampoline near ntdll.
		targetTrampolineData = reinterpret_cast<uint8_t *>(VirtualAllocEx(processHandle, reinterpret_cast<LPVOID>(address), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)); 
		if(targetTrampolineData)
			break;
		address += 0x100000;
	}
	WriteProcessMemory(processHandle, targetTrampolineData, trampolineData, trampolineSize, nullptr);
	
	//patch
	patchFunction(processHandle, patchData->ntCreateFile, reinterpret_cast<size_t>(targetTrampolineData));
	patchFunction(processHandle, patchData->ntReadFile, reinterpret_cast<size_t>(targetTrampolineData + 100));
	patchFunction(processHandle, patchData->ntWriteFile, reinterpret_cast<size_t>(targetTrampolineData + 200));
	patchFunction(processHandle, patchData->ntDeviceIoControlFile, reinterpret_cast<size_t>(targetTrampolineData + 300));

	delete [] trampolineData;
	delete [] originalCode;
}

void Patcher::patchProcess(void *processHandle)
{
	uint8_t *targetCodeBase = reinterpret_cast<uint8_t *>(VirtualAllocEx(processHandle, nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ));
#ifdef _WIN64
	BOOL isWow64;
	IsWow64Process(processHandle, &isWow64);
	if(!isWow64)
	{
		if(!WriteProcessMemory(processHandle, targetCodeBase, reinterpret_cast<LPCVOID>(stubData64), sizeof(stubData64), nullptr))
			throw std::exception("WriteProcessMemory failed");
		patch<TargetData64>(processHandle, &patchData, targetCodeBase);
	}
	else
	{
#endif
		if(!WriteProcessMemory(processHandle, targetCodeBase, reinterpret_cast<LPCVOID>(stubData32), sizeof(stubData32), nullptr))
			throw std::exception("WriteProcessMemory failed");
#ifdef _WIN64
		patch<TargetData32>(processHandle, &patchDataWoW64, targetCodeBase);
	}
#else
		patch<TargetData32>(processHandle, &patchData, targetCodeBase);
#endif
}

void Patcher::initPatch()
{
	HMODULE ntdllBase = GetModuleHandle(L"ntdll.dll");
	patchData.ntdllBase = reinterpret_cast<size_t>(ntdllBase);
	patchData.ntCreateFile = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtCreateFile"));
	patchData.ntWriteFile = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtWriteFile"));
	patchData.ntReadFile = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtReadFile"));
	patchData.ntDeviceIoControlFile = reinterpret_cast<size_t>(GetProcAddress(ntdllBase, "NtDeviceIoControlFile"));
	
#ifdef _WIN64
	patchData.syscallSize = 11; //mov r10, rcx; mov eax, <syscallno>; syscall; retn
	patchData.HookedNtCreateFile = HookedNtCreateFileAddr64;
	patchData.HookedNtReadFile = HookedNtReadFileAddr64;
	patchData.HookedNtWriteFile = HookedNtWriteFileAddr64;
	patchData.HookedNtDeviceIoControlFile = HookedNtDeviceIoControlFileAddr64;
#else
	patchData.syscallSize = 15; //mov eax, <syscallno>; call dword ptr fs:[0xc0]; retn 0xnn; (wow64)
								//mov eax, <syscallno>; mov edx, 0x7ffe0300; call [edx]; retn 0xnn;
	patchData.HookedNtCreateFile = HookedNtCreateFileAddr32;
	patchData.HookedNtReadFile = HookedNtReadFileAddr32;
	patchData.HookedNtWriteFile = HookedNtWriteFileAddr32;
	patchData.HookedNtDeviceIoControlFile = HookedNtDeviceIoControlFileAddr32;
#endif

	//TODO: patchDataWoW64;
#ifdef _WIN64
	patchDataWoW64.syscallSize = 15;
	patchDataWoW64.HookedNtCreateFile = HookedNtCreateFileAddr32;
	patchDataWoW64.HookedNtReadFile = HookedNtReadFileAddr32;
	patchDataWoW64.HookedNtWriteFile = HookedNtWriteFileAddr32;
	patchDataWoW64.HookedNtDeviceIoControlFile = HookedNtDeviceIoControlFileAddr32;
#endif 
}
