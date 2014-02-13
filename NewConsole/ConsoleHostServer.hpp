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

	void sendPacketHeader(uint16_t op, uint32_t size);
	void sendPacketData(const uint8_t *data, size_t size);

	template<typename T>
	void sendPacket(uint16_t op, const T *data)
	{
		sendPacketHeader(op, sizeof(T));
		sendPacketData(reinterpret_cast<const uint8_t *>(data), sizeof(T));
	}
	void sendPacketWithData(uint16_t op, const uint8_t *data, size_t size)
	{
		sendPacketHeader(op, static_cast<uint32_t>(size));
		sendPacketData(data, size);
	}
	template<typename T>
	void sendPacketData(const T* data)
	{
		sendPacketData(reinterpret_cast<const uint8_t *>(data), sizeof(T));
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
	static bool patchProcess(void *processHandle);
	static ConsoleHost *findConsoleHostByPid(uint32_t pid);
};