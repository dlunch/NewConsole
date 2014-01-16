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

		wchar_t fileName[255];
		lstrcpyn(fileName, reinterpret_cast<LPCWSTR>(data + sizeof(HandleCreateFileRequest)), request->fileNameLen); //eabuffer follows.
		fileName[request->fileNameLen / 2] = 0;

		if(wcsstr(fileName, L"\\Device\\ConDrv") || wcsstr(fileName, L"\\Input") || wcsstr(fileName, L"\\Output") || wcsstr(fileName, L"\\Reference"))
			response.returnFake = true;
		else
			response.returnFake = false;
		
		if(wcsstr(fileName, L"\\Connect"))
		{
			response.returnFake = true;
			void *EaBuffer = data + sizeof(HandleCreateFileRequest) + request->fileNameLen;
			//TODO
		}

		ConsoleHostServer::sendPacket(fromPipe, HandleCreateFile, &response);
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