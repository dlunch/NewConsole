#include "ConsoleHost.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "ConsoleHostServer.h"
#include "TargetProtocol.h"
#include "Win32Structure.h"

ConsoleHost::ConsoleHost(const std::wstring &process)
{
	try
	{
		ConsoleHostServer::registerConsoleHost(this);
		
		STARTUPINFO si;
		PROCESS_INFORMATION pi;

		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		si.dwFlags = STARTF_FORCEOFFFEEDBACK;

		CreateProcess(nullptr, const_cast<wchar_t *>(process.c_str()), nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);
		childProcess_ = pi.hProcess;
		childProcessId_ = pi.dwProcessId;

		ConsoleHostServer::patchProcess(pi.hProcess);

		ResumeThread(pi.hThread);
		CloseHandle(pi.hThread);

		//default mode
		inputMode_ = ENABLE_ECHO_INPUT | ENABLE_EXTENDED_FLAGS | ENABLE_INSERT_MODE | ENABLE_LINE_INPUT | ENABLE_MOUSE_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE;
		outputMode_ = ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT;
	}
	catch(...)
	{
		cleanup();
		throw;
	}
}

void ConsoleHost::cleanup()
{
	ConsoleHostServer::unRegisterConsoleHost(this);
	TerminateProcess(childProcess_, 0);
	CloseHandle(childProcess_);
}

ConsoleHost::~ConsoleHost()
{
	cleanup();
}

void ConsoleHost::handlePacket(ConsoleHostConnection *connection, uint16_t op, uint32_t size, uint8_t *data)
{
	if(op == Initialize)
	{
		InitializeRequest *req = reinterpret_cast<InitializeRequest *>(data);
		InitializeResponse response;

		HANDLE resultHandle;
		DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), childProcess_, &resultHandle, 0, TRUE, DUPLICATE_SAME_ACCESS);
		response.parentProcessHandle = reinterpret_cast<uint64_t>(resultHandle);

		connection->sendPacket(Initialize, &response);
	}
	else if(op == HandleCreateFile)
	{
		HandleCreateFileRequest *request = reinterpret_cast<HandleCreateFileRequest *>(data);
		HandleCreateFileResponse response;
		response.returnFake = false;

		wchar_t fileName[255];
		lstrcpyn(fileName, reinterpret_cast<LPCWSTR>(data + sizeof(HandleCreateFileRequest)), request->fileNameLen); //eabuffer follows.
		fileName[request->fileNameLen / 2] = 0;

		if(!wcsncmp(fileName, L"\\Device\\ConDrv", 14) || !wcsncmp(fileName, L"\\Input", 6) || !wcsncmp(fileName, L"\\Output", 7) || !wcsncmp(fileName, L"\\Reference", 10))
			response.returnFake = true;	
		else if(!wcsncmp(fileName, L"\\Connect", 8))
		{
			response.returnFake = true;
			void *EaBuffer = data + sizeof(HandleCreateFileRequest) + request->fileNameLen;
			//TODO
		}
		else
			__nop();

		connection->sendPacket(HandleCreateFile, &response);
	}
	else if(op == HandleReadFile)
	{
		HandleReadFileRequest *request = reinterpret_cast<HandleReadFileRequest *>(data);

		size_t size;
		uint8_t *buffer = getInputBuffer(request->readSize, &size);

		connection->sendPacket(HandleReadFile, buffer, size);
	}
	else if(op == HandleWriteFile)
	{
		uint8_t *buf = reinterpret_cast<uint8_t *>(data);

		handleWrite(buf, size);

		HandleWriteFileResponse response;
		response.writtenSize = size;

		connection->sendPacket(HandleWriteFile, &response);
	}
	else if(op == HandleDeviceIoControlFile)
	{
		HandleDeviceIoControlFileRequest *request = reinterpret_cast<HandleDeviceIoControlFileRequest *>(data);
		uint8_t *inputBuf = data + sizeof(HandleDeviceIoControlFileRequest);

		if(request->code == 0x500037) //Win8.1: Called in ConsoleLaunchServerProcess
		{
			//inputBuf is RTL_USER_PROCESS_PARAMETERS, but we don't use that.
			
			//no output
			connection->sendPacket(HandleDeviceIoControlFile);
		}
		else if(request->code == 0x500023) //Win8.1: Called in ConsoleCommitState
		{
			//kernelbase call SetInformationProcess(ProcessConsoleHostProcess) with result of this ioctl.
			//set outputbuffer to console host process's pid.
			size_t pid = GetCurrentProcessId();
			connection->sendPacket(HandleDeviceIoControlFile, &pid);
		}
		else if(request->code = 0x500016) //Win8.1: Called in ConsoleCallServerGeneric
		{
			//no output
#pragma pack(push, 4)
			struct ConsoleCallServerData
			{
				void *requestHandle;
				uint32_t unk1;
				uint32_t unk2;
				uint32_t unk3;
				uint32_t unk4;
				void *RequestDataPtr;
			};

			struct ConsoleCallServerRequestData
			{
				uint32_t requestCode;
				uint32_t unk;
				uint32_t data;
			};
			struct WriteConsoleRequestData
			{
				uint32_t dataSize;
				uint32_t unk;
				void *dataPtr;
				uint32_t unk1;
				uint32_t unk2;
				uint32_t unk3;
				uint32_t unk4;
			};
#pragma pack(pop)

			ConsoleCallServerRequestData requestData;
			ConsoleCallServerData *callData = reinterpret_cast<ConsoleCallServerData *>(inputBuf);
			ReadProcessMemory(childProcess_, reinterpret_cast<LPCVOID>(callData->RequestDataPtr), &requestData, sizeof(ConsoleCallServerRequestData), nullptr);

			if(requestData.requestCode == 0x1000008) //SetTEBLangID
				requestData.data = 0;
			else if(requestData.requestCode == 0x1000000) //GetConsoleCP
				requestData.data = CP_UTF8;
			else if(requestData.requestCode == 0x1000002) //SetConsoleMode
				requestData.data = 0;
			else if(requestData.requestCode == 0x1000001) //GetConsoleMode
				requestData.data = 0;
			else if(requestData.requestCode == 0x2000014) //GetConsoleTitle
				__nop();
			else if(requestData.requestCode == 0x2000007) //GetConsoleScreenBufferInfoEx
				__nop();
			else if(requestData.requestCode == 0x1000006) //WriteConsole
			{
				WriteConsoleRequestData *request = reinterpret_cast<WriteConsoleRequestData *>(inputBuf + sizeof(ConsoleCallServerData));
				uint8_t *writeData = new uint8_t[request->dataSize];
				ReadProcessMemory(childProcess_, reinterpret_cast<LPCVOID>(request->dataPtr), writeData, request->dataSize, nullptr);

				if(requestData.data == 1)
				{
					//input is unicode
					int size = WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<LPCWCH>(writeData), request->dataSize / 2, nullptr, 0, 0, nullptr);
					uint8_t *utf8Data = new uint8_t[size + 1];
					WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<LPCWCH>(writeData), -1, reinterpret_cast<LPSTR>(utf8Data), size, 0, nullptr);

					handleWrite(utf8Data, size);
				}
				else
					handleWrite(writeData, request->dataSize);

				delete [] writeData;

				requestData.data = static_cast<uint32_t>(request->dataSize);
			}
			else if(requestData.requestCode == 0x1000005) //ReadConsole
			{
				__nop();
			}
			else
				__nop();

			WriteProcessMemory(childProcess_, reinterpret_cast<LPVOID>(reinterpret_cast<size_t>(callData->RequestDataPtr) + 8), &requestData.data, sizeof(uint32_t), nullptr);

			connection->sendPacket(HandleDeviceIoControlFile);
		}
		else
			__debugbreak();
	}
	else if(op == HandleCreateUserProcess)
	{
		HandleCreateUserProcessRequest *request = reinterpret_cast<HandleCreateUserProcessRequest *>(data);

		request = request;
	}
	else if(op == HandleLPCMessage)
	{
		LPC_MESSAGE *lpcHeader = reinterpret_cast<LPC_MESSAGE *>(data);

		struct ConsoleAPIMessageHeader
		{
			size_t CsrCaptureData;
			size_t ApiNumber;
			uint32_t Status;
			uint32_t Reserved;
		};

		ConsoleAPIMessageHeader *messageHeader = reinterpret_cast<ConsoleAPIMessageHeader *>(data + sizeof(LPC_MESSAGE));

		HandleLPCMessageResponse response;
		response.callOriginal = true;
		connection->sendPacket(HandleLPCMessage, &response);
	}
}

void ConsoleHost::handleDisconnected(ConsoleHostConnection *connection)
{

}

void ConsoleHost::writeToConsole(const std::wstring &string)
{
}

uint8_t *ConsoleHost::getInputBuffer(size_t requestSize, size_t *resultSize)
{
	return nullptr;
}

void ConsoleHost::handleWrite(uint8_t *buffer, size_t bufferSize)
{

}
