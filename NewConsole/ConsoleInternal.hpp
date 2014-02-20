#pragma once

#include <cstdint>

#pragma pack(push, 4)
//New~~ structs are used for new console architecture (>=win8)
struct NewConsoleCallServerData
{
	void *requestHandle;
	uint32_t data1;
	uint32_t data2;
	uint32_t data3;
	uint32_t data4;
	void *requestDataPtr;
};

struct NewConsoleCallServerGenericData
{
	uint32_t unk1;
	uint32_t unk2;
	void *responsePtr;
};

struct NewConsoleCallServerRequestData
{
	uint32_t requestCode;
	uint32_t unk;
	uint32_t data;
	uint32_t data1;
};
struct NewWriteConsoleRequestData
{
	uint32_t dataSize;
	uint32_t unk;
	void *dataPtr;
	uint32_t unk1;
	uint32_t unk2;
	void *responsePtr;
};

struct NewReadConsoleRequestData
{
	uint32_t unk1;
	uint32_t unk2;
	void *unkPtr;
	uint32_t unk3;
	uint32_t unk4;
	void *dataPtr2;
	uint32_t unk5;
	uint32_t unk6;
	void *data2Ptr;
	uint32_t sizeToRead;
	uint32_t unk7;
	void *dataPtr;
};

struct NewGetConsoleTitleRequestData
{
	uint32_t unk1;
	uint32_t unk2;
	void *responsePtr;
	uint32_t dataSize;
	uint32_t unk4;
	void *dataPtr;
};

struct NewReadConsoleInputControlData
{
	uint32_t response;
	uint32_t nInitialBytes;
	uint32_t ctrlWakeupMask;
	uint32_t unk;
};

struct GetConsoleScreenBufferInfoExResponse
{
	COORD size;					//+0
	COORD cursorPos;			//+4
	COORD tlcoord;				//+8
	uint16_t attribute;			//+12
	COORD brcoord;				//+14
	COORD maxWindowSize;		//+18
	uint16_t popupAttributes;	//+22
	uint8_t fullscreenSupported;//+24
	uint8_t pad1;				//+25
	uint16_t pad2;				//+27
	uint32_t colorTable[16];	//+28
};
struct CSRSSLPCMessageHeader
{
	LPC_MESSAGE LPCHeader;

	size_t CsrCaptureData;
	size_t ApiNumber;
	uint32_t Status;
	uint32_t Reserved;
};

enum CSRSSAPI
{
	CSRSSApiOpenConsole,
	CSRSSApiGetConsoleMode,
	CSRSSApiSetConsoleMode,
	CSRSSApiReadConsole,
	CSRSSApiWriteConsole,
	CSRSSApiGetConsoleTitle,
	CSRSSApiGetConsoleScreenBufferInfo,
	CSRSSApiGetConsoleLangId,
	CSRSSApiVerifyConsoleIoHandle,
	CSRSSApiGetConsoleCP,
	CSRSSApiSetConsoleTitle,
};

struct CSRSSGetSetConsoleModeData
{
	void *handle;
	uint32_t mode;
};

struct CSRSSGetSetCPData
{
	uint32_t isInput;
	uint32_t codepage;
};

struct CSRSSVerifyConsoleIoHandleData
{
	size_t result;
	void *handle;
};

struct CSRSSWriteConsoleData
{
	void *handle;
	uint8_t data[0x50];
	void *dataPtr;
	size_t dataSize;
	size_t unk;
	uint8_t isEmbedded;
	uint8_t isWideChar;
};

#pragma pack(push, 1)
struct CSRSSReadConsoleData
{
	void *handle;
	uint16_t exeNameSize;
	uint8_t data[0x56];
	void *dataPtr;
	uint32_t sizeRead;
	uint32_t sizeToRead;
	uint32_t unk1;
	uint32_t unk2;
	uint32_t unk3;
	uint8_t isWideChar;
};
#pragma pack(pop)

struct CSRSSConsoleClientConnectData
{
	void *consoleHandle;	//0		//0
	size_t unk;				//8		//4
	void *inputHandle;		//16	//8
	void *outputHandle;		//24	//12
	void *errorHandle;		//32	//16
	size_t unk2;			//40	//20
	size_t unk3;			//48	//24
	size_t unk4;			//56	//28
	uint32_t unk5;			//64	//32
	uint32_t flag;			//68	//36
};

struct CSRSSGetConsoleScreenBufferInfoExResponse
{
	void *handle;
	GetConsoleScreenBufferInfoExResponse data;
};

#pragma pack(pop)
