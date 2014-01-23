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
	HANDLE pipe = CreateNamedPipe(L"\\\\.\\pipe\\" PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, 0, PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, nullptr);
	ConsoleHostConnection *connection = new ConsoleHostConnection(pipe);
	CreateIoCompletionPort(pipe, consoleHostServerData_->iocp, reinterpret_cast<ULONG_PTR>(connection), 0);
	
	IOOperation *op = new IOOperation;
	ZeroMemory(op, sizeof(IOOperation));
	op->type = Connect;

	ConnectNamedPipe(pipe, op);
}

size_t __stdcall ConsoleHostServer::iocpThread(LPVOID)
{
	while(true)
	{
		DWORD transferred;
		ConsoleHostConnection *connection;
		IOOperation *op;
		GetQueuedCompletionStatus(consoleHostServerData_->iocp, &transferred, reinterpret_cast<ULONG_PTR *>(&connection), reinterpret_cast<LPOVERLAPPED *>(&op), INFINITE);

		if(op)
		{
			if(op->type == Connect)
			{
				connection->connected();
				listenPipe();
			}
			else if(op->type == ReadHeader && transferred != 0)
				connection->headerReceived(op);
			else if(op->type == ReadData && transferred != 0)
				connection->dataReceived(op, transferred);
			else if(op->type != Write)
			{
				connection->disconnected(op);
				delete connection;
			}

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

ConsoleHost *ConsoleHostServer::findConsoleHostByPid(uint32_t pid)
{
	ConsoleHost *foundHost;
	for(auto &i : consoleHostServerData_->waitingHosts)
	{
		if(i->childProcessId_ == pid)
		{
			foundHost = i;
			break;
		}
	}
	consoleHostServerData_->waitingHosts.remove(foundHost);
	return foundHost;
}


ConsoleHostConnection::ConsoleHostConnection(void *pipe) : pipe_(pipe), host_(nullptr), buf_(nullptr), totalReceived_(0), header_(new PacketHeader)
{

}

ConsoleHostConnection::~ConsoleHostConnection()
{
	if(pipe_ != INVALID_HANDLE_VALUE)
		CloseHandle(pipe_);
	if(buf_)
		delete [] buf_;
	delete header_;
}

void ConsoleHostConnection::connected()
{
	readPacketHeader();
}

void ConsoleHostConnection::writePipe(uint8_t *data, size_t size)
{
	IOOperation *op = new IOOperation;
	ZeroMemory(op, sizeof(IOOperation));
	op->type = Write;
	
	WriteFile(pipe_, data, static_cast<DWORD>(size), nullptr, op);
}

void ConsoleHostConnection::readPipe(uint8_t *buf, size_t size, OperationType type)
{
	IOOperation *op = new IOOperation;
	ZeroMemory(op, sizeof(IOOperation));
	op->type = type;
	
	ReadFile(pipe_, buf, static_cast<DWORD>(size), nullptr, op);
}

void ConsoleHostConnection::readPacketHeader()
{
	readPipe(reinterpret_cast<uint8_t *>(header_), sizeof(PacketHeader), ReadHeader);
}

void ConsoleHostConnection::sendPacket_(uint32_t op, uint8_t *data, size_t size)
{
	PacketHeader header;
	header.op = op;
	header.length = static_cast<uint32_t>(size);

	writePipe(reinterpret_cast<uint8_t *>(&header), sizeof(PacketHeader));
	if(size)
		writePipe(data, size);
}

void ConsoleHostConnection::headerReceived(IOOperation *op)
{
	buf_ = new uint8_t[header_->length];
	readPipe(buf_, header_->length, ReadData);
}

void ConsoleHostConnection::dataReceived(IOOperation *op, size_t receivedSize)
{
	totalReceived_ += receivedSize;
	if(totalReceived_ < header_->length)
	{
		readPipe(buf_ + totalReceived_, header_->length - totalReceived_, ReadData);
		return;
	}
	if(header_->op == Initialize)
	{
		InitializeRequest *request = reinterpret_cast<InitializeRequest *>(buf_);
		host_ = ConsoleHostServer::findConsoleHostByPid(request->pid);
		if(host_)
			host_->setConnection(this);
	}
	if(host_)
		host_->handlePacket(header_->op, header_->length, buf_);

	delete [] buf_;
	buf_ = nullptr;
	totalReceived_ = 0;
	readPacketHeader();
}

void ConsoleHostConnection::disconnected(IOOperation *op)
{
	if(host_)
		host_->handleDisconnected();
	CloseHandle(pipe_);
	pipe_ = INVALID_HANDLE_VALUE;
}
