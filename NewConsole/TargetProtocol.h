#pragma once

#include <cstdint>

struct PacketHeader
{
	uint16_t op;
	uint32_t length;
};

enum PacketOp
{
	Initialize,
	HandleCreateFile,
	HandleReadFile,
	HandleWriteFile,
	HandleDeviceIoControlFile,
	HandleCreateUserProcess,
	HandleLPCConnect,
	HandleLPCMessage,
	HandleDuplicateObject,
};

#pragma pack(push, 4)
struct InitializeRequest
{
	uint32_t pid;
};

struct InitializeResponse
{
	uint64_t parentProcessHandle;
};

struct HandleCreateFileRequest
{
	uint32_t fileNameLen;
};

struct HandleCreateFileResponse
{
	uint8_t returnFake;
	void *fakeHandle;
};

struct HandleReadFileRequest
{
	uint32_t sizeToRead;
};

struct HandleWriteFileResponse
{
	uint32_t writtenSize;
};

struct HandleDeviceIoControlFileRequest
{
	void *handle;
	uint32_t code;
	//data follows
};

//this method will be sent after proecss creation.
struct HandleCreateUserProcessRequest
{
	void *processHandle;
};

struct HandleLPCMessageRequest
{
	void *requestPointer;
};

struct HandleLPCMessageResponse
{
	uint8_t callOriginal;
};

struct HandleDuplicateObjectRequest
{
	void *handle;
};

struct HandleDuplicateObjectResponse
{
	void *fakeHandle;
};

struct LPCConnectRequest
{
	size_t serverBase;
	size_t clientBase;
};

#pragma pack(pop)

#define PIPE_NAME L"newconsole"
