#include "ConsoleHostServer.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <list>

#include "TargetProtocol.h"
#include "ConsoleHost.h"
#include "Patcher.h"

struct ConsoleHostServerData
{
	HANDLE jobObject;
	HANDLE iocp;
	std::list<ConsoleHost *> waitingHosts;
};

enum OperationType
{
	Connect,
	ReadHeader,
	ReadData,
	Write,
};

struct IOOperation : public OVERLAPPED
{
	OperationType type;
	HANDLE handle;
	uint8_t *buf;
};

struct ConnectionData
{
	ConnectionData() : host(nullptr) {}
	ConsoleHost *host;
	PacketHeader header;
};
ConsoleHostServerData *ConsoleHostServer::consoleHostServerData_;

void ConsoleHostServer::initialize()
{
	DWORD unused;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0, };

	Patcher::initPatch();

	consoleHostServerData_ = new ConsoleHostServerData();
	consoleHostServerData_->jobObject = CreateJobObject(nullptr, nullptr);
	jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	SetInformationJobObject(consoleHostServerData_->jobObject, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli)); //kill target process if this process die.

	consoleHostServerData_->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
	CloseHandle(CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&ConsoleHostServer::iocpThread), nullptr, 0, &unused));

	listenPipe();
}

void ConsoleHostServer::listenPipe()
{
	ConnectionData *connectionData = new ConnectionData;
	HANDLE pipe = CreateNamedPipe(L"\\\\.\\pipe\\" PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, 0, PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, nullptr);
	CreateIoCompletionPort(pipe, consoleHostServerData_->iocp, reinterpret_cast<ULONG_PTR>(connectionData), 0);
	
	IOOperation *op = new IOOperation;
	ZeroMemory(op, sizeof(IOOperation));
	op->type = Connect;
	op->handle = pipe;

	ConnectNamedPipe(pipe, op);
}

void ConsoleHostServer::writePipe(HANDLE pipe, uint8_t *data, size_t size)
{
	IOOperation *op = new IOOperation;
	ZeroMemory(op, sizeof(IOOperation));
	op->type = Write;
	op->handle = pipe;
	
	WriteFile(pipe, data, static_cast<DWORD>(size), nullptr, op);
}

void ConsoleHostServer::readPipe(HANDLE pipe, size_t size, OperationType type)
{
	IOOperation *op = new IOOperation;
	ZeroMemory(op, sizeof(IOOperation));
	op->type = type;
	op->handle = pipe;
	op->buf = new uint8_t[size];
	
	ReadFile(pipe, op->buf, static_cast<DWORD>(size), nullptr, op);
}

void ConsoleHostServer::readPacketHeader(HANDLE pipe)
{
	readPipe(pipe, sizeof(PacketHeader), ReadHeader);
}

void ConsoleHostServer::sendPacket_(HANDLE pipe, uint32_t op, uint8_t *data, size_t size)
{
	PacketHeader header;
	header.op = op;
	header.length = static_cast<uint32_t>(size);

	writePipe(pipe, reinterpret_cast<uint8_t *>(&header), sizeof(PacketHeader));
	writePipe(pipe, data, size);
}

void ConsoleHostServer::headerReceived(ConnectionData *connectionData, IOOperation *op)
{
	CopyMemory(&connectionData->header, op->buf, sizeof(PacketHeader));

	readPipe(op->handle, connectionData->header.length, ReadData);
}

void ConsoleHostServer::dataReceived(ConnectionData *connectionData, IOOperation *op)
{
	if(connectionData->header.op == Initialize)
	{
		InitializeRequest *request = reinterpret_cast<InitializeRequest *>(op->buf);
		ConsoleHost *foundHost = nullptr;
		for(auto &i : consoleHostServerData_->waitingHosts)
		{
			if(i->childProcessId_ == request->pid)
			{
				foundHost = i;
				break;
			}
		}
		connectionData->host = foundHost;
		consoleHostServerData_->waitingHosts.remove(foundHost);
	}
	if(connectionData->host)
		connectionData->host->handlePacket(op->handle, connectionData->header.op, connectionData->header.length, op->buf);
	readPacketHeader(op->handle);
}

void ConsoleHostServer::disconnected(ConnectionData *connectionData, IOOperation *op)
{
	if(connectionData->host)
		connectionData->host->handleDisconnected();
	delete connectionData;
}

size_t __stdcall ConsoleHostServer::iocpThread(LPVOID)
{
	while(true)
	{
		DWORD transferred;
		ConnectionData *connectionData;
		IOOperation *op;
		GetQueuedCompletionStatus(consoleHostServerData_->iocp, &transferred, reinterpret_cast<ULONG_PTR *>(&connectionData), reinterpret_cast<LPOVERLAPPED *>(&op), INFINITE);

		if(op)
		{
			if(op->type == Connect)
			{
				readPacketHeader(op->handle);
				listenPipe();
			}
			else if(op->type == ReadHeader && transferred != 0)
				headerReceived(connectionData, op);
			else if(op->type == ReadData && transferred != 0)
				dataReceived(connectionData, op);
			else if(op->type != Write)
				disconnected(connectionData, op);

			if(op->buf)
				delete [] op->buf;
			delete op;
		}
	}
}

void ConsoleHostServer::registerConsoleHost(ConsoleHost *host)
{
	consoleHostServerData_->waitingHosts.push_back(host);
}

void ConsoleHostServer::unRegisterConsoleHost(ConsoleHost *host)
{
	consoleHostServerData_->waitingHosts.remove(host);
}

void ConsoleHostServer::patchProcess(void *processHandle)
{
	AssignProcessToJobObject(consoleHostServerData_->jobObject, processHandle);
	Patcher::patchProcess(processHandle);
}