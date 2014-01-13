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
	HandleDeviceIoControl,
};

#pragma pack(push, 4)

struct InitializeData
{
	uint32_t pid;
};

struct HandleCreateFileRequest
{
	wchar_t fileName[255];
};

struct HandleCreateFileResponse
{
	uint8_t returnFake;
};

#pragma pack(pop)

#define PIPE_NAME L"newconsole"
