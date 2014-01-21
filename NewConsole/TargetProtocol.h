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
};

struct HandleReadFileRequest
{
	uint32_t readSize;
};

struct HandleWriteFileResponse
{
	uint32_t writtenSize;
};

struct HandleDeviceIoControlFileRequest
{
	uint32_t code;
	//data follows
};

//this method will be sent after proecss creation.
struct HandleCreateUserProcessRequest
{
	uint64_t processHandle;
};

struct HandleLPCMessageResponse
{
	uint8_t callOriginal;
};

struct HandleLPCConnectResponse
{
	uint8_t returnFake;
};

#pragma pack(pop)

#define PIPE_NAME L"newconsole"
