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
	uint32_t firstRequest;
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
	uint32_t returnFake;
	uint64_t fakeHandle;
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
	uint64_t handle;
	uint32_t code;
	//data follows
};

//this method will be sent after proecss creation.
struct HandleCreateUserProcessRequest
{
	uint64_t processHandle;
};

struct HandleLPCMessageRequest
{
	uint64_t requestPointer;
};

struct HandleLPCMessageResponse
{
	uint32_t callOriginal;
};

struct HandleDuplicateObjectRequest
{
	uint64_t handle;
};

struct HandleDuplicateObjectResponse
{
	uint64_t fakeHandle;
};

struct LPCConnectRequest
{
	uint64_t serverBase;
	uint64_t clientBase;
};

#pragma pack(pop)

#define PIPE_NAME L"newconsole"
