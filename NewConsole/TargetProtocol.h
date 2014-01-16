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
};

#pragma pack(push, 4)
struct InitializeRequest
{
	uint32_t pid;
};

struct InitializeResponse
{
	uint32_t parentProcessHandle;
};

struct HandleCreateFileRequest
{
	uint32_t fileNameLen;
};

struct HandleCreateFileResponse
{
	uint8_t returnFake;
};

struct HandleDeviceIoControlFileRequest
{
	uint32_t code;
	//data follows
};

//this method will be sent after proecss creation.
struct HandleCreateUserProcessRequest
{
	uint32_t processHandle;
};

#pragma pack(pop)

#define PIPE_NAME L"newconsole"
