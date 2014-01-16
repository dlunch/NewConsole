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

		if(wcsstr(fileName, L"ConDrv") || wcsstr(fileName, L"\\Input") || wcsstr(fileName, L"\\Output") || wcsstr(fileName, L"\\Reference") || wcsstr(fileName, L"\\Connect"))
			response.returnFake = true;
		else
			response.returnFake = false;

		ConsoleHostServer::sendPacket(fromPipe, HandleCreateFile, &response);
	}
	else if(op == HandleReadFile)
	{
		HandleReadFileRequest *request = reinterpret_cast<HandleReadFileRequest *>(data);

		request = request;
	}
	else if(op == HandleWriteFile)
	{
		uint8_t *buf = reinterpret_cast<uint8_t *>(data);

		buf = buf;
	}
	else if(op == HandleDeviceIoControlFile)
	{
		HandleDeviceIoControlFileRequest *request = reinterpret_cast<HandleDeviceIoControlFileRequest *>(data);
		uint8_t *inputBuf = data + sizeof(HandleDeviceIoControlFileRequest);

		request = request;
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