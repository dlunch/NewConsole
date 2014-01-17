#include "ConsoleHost.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "ConsoleHostServer.h"
#include "TargetProtocol.h"

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

void ConsoleHost::handlePacket(HANDLE fromPipe, uint16_t op, uint32_t size, uint8_t *data)
{
	if(op == Initialize)
	{
		InitializeRequest *req = reinterpret_cast<InitializeRequest *>(data);
		InitializeResponse response;

		HANDLE resultHandle;
		DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), childProcess_, &resultHandle, 0, TRUE, DUPLICATE_SAME_ACCESS);
		response.parentProcessHandle = reinterpret_cast<uint32_t>(resultHandle);

		ConsoleHostServer::sendPacket(fromPipe, Initialize, &response);
	}
	else if(op == HandleCreateFile)
	{
		HandleCreateFileRequest *request = reinterpret_cast<HandleCreateFileRequest *>(data);
		HandleCreateFileResponse response;
		response.returnFake = false;

		wchar_t fileName[255];
		lstrcpyn(fileName, reinterpret_cast<LPCWSTR>(data + sizeof(HandleCreateFileRequest)), request->fileNameLen); //eabuffer follows.
		fileName[request->fileNameLen / 2] = 0;

		if(wcsstr(fileName, L"\\Device\\ConDrv") || wcsstr(fileName, L"\\Input") || wcsstr(fileName, L"\\Output") || wcsstr(fileName, L"\\Reference"))
			response.returnFake = true;	
		else if(wcsstr(fileName, L"\\Connect"))
		{
			response.returnFake = true;
			void *EaBuffer = data + sizeof(HandleCreateFileRequest) + request->fileNameLen;
			//TODO
		}

		ConsoleHostServer::sendPacket(fromPipe, HandleCreateFile, &response);
	}
	else if(op == HandleReadFile)
	{
		HandleReadFileRequest *request = reinterpret_cast<HandleReadFileRequest *>(data);

		char data[] = "dir\r\n";

		ConsoleHostServer::sendPacket(fromPipe, HandleReadFile, reinterpret_cast<uint8_t *>(data), 6);

	}
	else if(op == HandleWriteFile)
	{
		uint8_t *buf = reinterpret_cast<uint8_t *>(data);

		HandleWriteFileResponse response;
		response.writtenSize = size;

		ConsoleHostServer::sendPacket(fromPipe, HandleWriteFile, &response);
	}
	else if(op == HandleDeviceIoControlFile)
	{
		HandleDeviceIoControlFileRequest *request = reinterpret_cast<HandleDeviceIoControlFileRequest *>(data);
		uint8_t *inputBuf = data + sizeof(HandleDeviceIoControlFileRequest);

		if(request->code == 0x500037) //Win8.1: Called in ConsoleLaunchServerProcess
		{
			//inputBuf is RTL_USER_PROCESS_PARAMETERS, but we don't use that.
			
			//no output
			ConsoleHostServer::sendPacket(fromPipe, HandleDeviceIoControlFile);
		}
		else if(request->code == 0x500023) //Win8.1: Called in ConsoleCommitState
		{
			//kernelbase call SetInformationProcess(ProcessConsoleHostProcess) with result of this ioctl.
			//set outputbuffer to console host process's pid.
			size_t pid = GetCurrentProcessId();
			ConsoleHostServer::sendPacket(fromPipe, HandleDeviceIoControlFile, &pid);
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
			};
#pragma pack(pop)

			ConsoleCallServerRequestData requestData;
			ConsoleCallServerData *callData = reinterpret_cast<ConsoleCallServerData *>(inputBuf);
			ReadProcessMemory(childProcess_, reinterpret_cast<LPCVOID>(callData->RequestDataPtr), &requestData, sizeof(ConsoleCallServerRequestData), nullptr);

			if(requestData.requestCode == 0x1000008) //SetTEBLangID
				requestData.data = 0;
			else if(requestData.requestCode == 0x1000000) //GetConsoleCP
				requestData.data = 65001;
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

			ConsoleHostServer::sendPacket(fromPipe, HandleDeviceIoControlFile);
		}
		else
			__debugbreak();
	}
	else if(op == HandleCreateUserProcess)
	{
		HandleCreateUserProcessRequest *request = reinterpret_cast<HandleCreateUserProcessRequest *>(data);

		request = request;
	}
}

void ConsoleHost::handleDisconnected()
{

}

void ConsoleHost::writeToConsole(const std::wstring &string)
{
}