#pragma once

#include <cstdint>

struct ConsoleHostServerData;
enum OperationType;
struct IOOperation;
class ConsoleHost;
struct PacketHeader;

class ConsoleHostConnection
{
	friend class ConsoleHostServer;
private:
	void *pipe_;
	ConsoleHost *host_;
	PacketHeader *header_;
	uint8_t *buf_;
	size_t totalReceived_;
	
	void sendPacket_(uint32_t op, const uint8_t *data, size_t size);
	void readPacketHeader();

	void writePipe(const uint8_t *data, size_t size);
	void readPipe(uint8_t *buf, size_t size, OperationType type);
	void headerReceived(IOOperation *op);
	void dataReceived(IOOperation *op, size_t receivedSize);
	void disconnected(IOOperation *op);
	void connected();
public:
	ConsoleHostConnection(void *pipe);
	~ConsoleHostConnection();

	template<typename T>
	void sendPacket(uint32_t op, T *data)
	{
		return sendPacket_( op, reinterpret_cast<uint8_t *>(data), sizeof(T));
	}
	void sendPacket(uint32_t op)
	{
		return sendPacket_(op, nullptr, 0);
	}
	void sendPacketWithData(uint32_t op, const uint8_t *data, size_t size)
	{
		return sendPacket_(op, data, size);
	}
};

//static class
class ConsoleHostServer
{
private:
	static ConsoleHostServerData *consoleHostServerData_;

	static size_t __stdcall iocpThread(void *);
	static void listenPipe();
	
public:
	static void initialize();
	static void registerConsoleHost(ConsoleHost *host);
	static void unRegisterConsoleHost(ConsoleHost *host);
	static void patchProcess(void *processHandle);
	static ConsoleHost *findConsoleHostByPid(uint32_t pid);
};