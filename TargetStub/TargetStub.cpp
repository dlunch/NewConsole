#include <cstdint>

#include <intrin.h>

#include "../NewConsole/Win32Structure.h"
#include "../NewConsole/TargetProtocol.h"

typedef uint32_t (__stdcall *NtCreateFile)(void **FileHandle, int DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, 
										 PLARGE_INTEGER AllocationSize, size_t FileAttributes, size_t ShareAccess, 
										 size_t CreateDisposition, size_t CreateOptions, void *EaBuffer, size_t EaLength); 
typedef uint32_t (__stdcall *NtWriteFile)(void *FileHandle, void *Event, void *ApcRoutine, void *ApcContext, PIO_STATUS_BLOCK IoStatusBlock, 
										void *Buffer, size_t Length, PLARGE_INTEGER ByteOffset, size_t *Key); 
typedef uint32_t (__stdcall *NtReadFile)(void *FileHandle, void *Event, void *ApcRoutine, void *ApcContext, PIO_STATUS_BLOCK IoStatusBlock, 
									   void *Buffer, size_t Length, PLARGE_INTEGER ByteOffset, size_t *Key); 
typedef uint32_t (__stdcall *NtDeviceIoControlFile)(void *FileHandle, void *Event, void *ApcRoutine, void *ApcContext, PIO_STATUS_BLOCK IoStatusBlock, 
												  size_t IoControlCode, void *InputBuffer, size_t InputBufferLength, void *OutputBuffer, 
												  size_t OutputBufferLength);

struct TargetData
{
	NtCreateFile originalNtCreateFile;
	NtDeviceIoControlFile originalNtDeviceIoControlFile;
	NtWriteFile originalNtWriteFile;
	NtReadFile originalNtReadFile;

	bool initialized;
	void *pipeHandle;
	uint8_t lastHandleId;
};

extern "C" {
__declspec(dllexport) uint32_t __stdcall HookedNtCreateFile(TargetData *targetData, void **FileHandle, int DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, 
									  PLARGE_INTEGER AllocationSize, size_t FileAttributes, size_t ShareAccess, 
									  size_t CreateDisposition, size_t CreateOptions, void *EaBuffer, size_t EaLength);

__declspec(dllexport) uint32_t __stdcall HookedNtReadFile(TargetData *targetData, void *FileHandle, void *Event, void *ApcRoutine, void *ApcContext, PIO_STATUS_BLOCK IoStatusBlock, 
									void *Buffer, size_t Length, PLARGE_INTEGER ByteOffset, size_t *Key);

__declspec(dllexport) uint32_t __stdcall HookedNtWriteFile(TargetData *targetData, void *FileHandle, void *Event, void *ApcRoutine, void *ApcContext, PIO_STATUS_BLOCK IoStatusBlock, 
									 void *Buffer, size_t Length, PLARGE_INTEGER ByteOffset, size_t *Key);

__declspec(dllexport) uint32_t __stdcall HookedNtDeviceIoControlFile(TargetData *targetData, void *FileHandle, void *Event, void *ApcRoutine, void *ApcContext, PIO_STATUS_BLOCK IoStatusBlock, 
											   size_t IoControlCode, void *InputBuffer, size_t InputBufferLength, void *OutputBuffer, size_t OutputBufferLength);
}

template<typename SrcType, typename DstType>
void copyMemory(DstType *dst, SrcType *src, size_t size)
{
	uint8_t *dst_ = reinterpret_cast<uint8_t *>(dst);
	uint8_t *src_ = reinterpret_cast<uint8_t *>(src);
	for(size_t i = 0; i < size; i ++)
		*dst_ ++ = *src_ ++;
}

void *openPipe(TargetData *targetData)
{
	void *handle = nullptr;
	IO_STATUS_BLOCK statusBlock;
	OBJECT_ATTRIBUTES attributes;
	UNICODE_STRING pipeName;
	uint8_t buf[58];

	*reinterpret_cast<uint32_t *>(buf) = 0x0044005c; //\\Device\\NamedPipe\\newconsole
	*reinterpret_cast<uint32_t *>(buf + 4) = 0x00760065;
	*reinterpret_cast<uint32_t *>(buf + 8) = 0x00630069;
	*reinterpret_cast<uint32_t *>(buf + 12) = 0x005c0065;
	*reinterpret_cast<uint32_t *>(buf + 16) = 0x0061004e;
	*reinterpret_cast<uint32_t *>(buf + 20) = 0x0065006d;
	*reinterpret_cast<uint32_t *>(buf + 24) = 0x00500064;
	*reinterpret_cast<uint32_t *>(buf + 28) = 0x00700069;
	*reinterpret_cast<uint32_t *>(buf + 32) = 0x005c0065;
	*reinterpret_cast<uint32_t *>(buf + 36) = 0x0065006e;
	*reinterpret_cast<uint32_t *>(buf + 40) = 0x00630077;
	*reinterpret_cast<uint32_t *>(buf + 44) = 0x006e006f;
	*reinterpret_cast<uint32_t *>(buf + 48) = 0x006f0073;
	*reinterpret_cast<uint32_t *>(buf + 52) = 0x0065006c;
	*reinterpret_cast<uint16_t *>(buf + 56) = 0;

	pipeName.Buffer = reinterpret_cast<wchar_t *>(buf);
	pipeName.Length = 56;
	pipeName.MaximumLength = 56;

	attributes.Length = sizeof(attributes);
	attributes.RootDirectory = nullptr;
	attributes.ObjectName = &pipeName;
	attributes.Attributes = 0;
	attributes.SecurityDescriptor = nullptr;
	attributes.SecurityQualityOfService = nullptr;

	targetData->originalNtCreateFile(&handle, GENERIC_READ | GENERIC_WRITE | FILE_GENERIC_READ | FILE_GENERIC_WRITE, 
				 &attributes, &statusBlock, 0, 0, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_ALERT, 0, 0);
	return handle;
}

template<typename T>
void writePipe(TargetData *targetData, uint16_t op, T *data)
{
	PacketHeader header;
	header.op = op;
	header.length = sizeof(T);

	IO_STATUS_BLOCK statusBlock;
	targetData->originalNtWriteFile(targetData->pipeHandle, 0, 0, 0, &statusBlock, &header, sizeof(header), 0, 0);
	targetData->originalNtWriteFile(targetData->pipeHandle, 0, 0, 0, &statusBlock, data, sizeof(T), 0, 0);
}

template<typename T>
uint32_t readPipe(TargetData *targetData, T *data)
{
	PacketHeader header;
	IO_STATUS_BLOCK statusBlock;
	targetData->originalNtReadFile(targetData->pipeHandle, 0, 0, 0, &statusBlock, &header, sizeof(PacketHeader), 0, 0);
	targetData->originalNtReadFile(targetData->pipeHandle, 0, 0, 0, &statusBlock, data, header.length, 0, 0);

	return header.op;
}

void initialize(TargetData *targetData)
{
	//send pid
#ifdef _WIN64
	TEB *teb = reinterpret_cast<TEB *>(__readgsqword(0x30));
	PEB64 *peb = reinterpret_cast<PEB64 *>(__readgsqword(0x60));
#elif defined(_WIN32)
	TEB *teb = reinterpret_cast<TEB *>(__readfsdword(0x18));
	PEB32 *peb = reinterpret_cast<PEB32 *>(__readfsdword(0x30));
#endif
	InitializeData packet;
	packet.pid = reinterpret_cast<uint32_t>(teb->ClientId.UniqueProcess);

	targetData->pipeHandle = openPipe(targetData);
	writePipe(targetData, Initialize, &packet);

	targetData->initialized = true;
}

uint32_t __stdcall HookedNtCreateFile(TargetData *targetData, void **FileHandle, int DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, 
									  PLARGE_INTEGER AllocationSize, size_t FileAttributes, size_t ShareAccess, 
									  size_t CreateDisposition, size_t CreateOptions, void *EaBuffer, size_t EaLength)
{
	if(!targetData->initialized)
		initialize(targetData);
	HandleCreateFileRequest request;
	HandleCreateFileResponse response;
	copyMemory(request.fileName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
	request.fileName[ObjectAttributes->ObjectName->Length / 2] = 0;
	writePipe(targetData, HandleCreateFile, &request);

	readPipe(targetData, &response);

	if(response.returnFake)
	{
		*reinterpret_cast<size_t *>(FileHandle) = 0xeeff00f3 | ((targetData->lastHandleId ++) << 8);
		return 0;
	}
	
	return targetData->originalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
									  CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

uint32_t __stdcall HookedNtReadFile(TargetData *targetData, void *FileHandle, void *Event, void *ApcRoutine, void *ApcContext, PIO_STATUS_BLOCK IoStatusBlock, 
									void *Buffer, size_t Length, PLARGE_INTEGER ByteOffset, size_t *Key)
{
	return targetData->originalNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

uint32_t __stdcall HookedNtWriteFile(TargetData *targetData, void *FileHandle, void *Event, void *ApcRoutine, void *ApcContext, PIO_STATUS_BLOCK IoStatusBlock, 
									 void *Buffer, size_t Length, PLARGE_INTEGER ByteOffset, size_t *Key)
{
	return targetData->originalNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

uint32_t __stdcall HookedNtDeviceIoControlFile(TargetData *targetData, void *FileHandle, void *Event, void *ApcRoutine, void *ApcContext, PIO_STATUS_BLOCK IoStatusBlock, 
											   size_t IoControlCode, void *InputBuffer, size_t InputBufferLength, void *OutputBuffer, size_t OutputBufferLength)
{
	return targetData->originalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
											   OutputBuffer, OutputBufferLength);
}

void entry() {}