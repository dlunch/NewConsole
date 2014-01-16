#pragma once

#include <cstdint>

struct ConsoleHostServerData;
enum OperationType;
struct IOOperation;
struct ConnectionData;
class ConsoleHost;

//static class
class ConsoleHostServer
{
private:
	static ConsoleHostServerData *consoleHostServerData_;

	static size_t __stdcall iocpThread(void *);
	static void listenPipe();
	static void writePipe(void *pipe, uint8_t *data, size_t size);
	static void readPipe(void *pipe, size_t size, OperationType type);
	static void readPacketHeader(void *pipe);
	static void headerReceived(ConnectionData *connectionData, IOOperation *op);
	static void dataReceived(ConnectionData *connectionData, IOOperation *op);
	static void disconnected(ConnectionData *connectionData, IOOperation *op);
	static void sendPacket_(void *pipe, uint32_t op, uint8_t *data, size_t size);
	
public:
	static void initialize();
	static void registerConsoleHost(ConsoleHost *host);
	static void unRegisterConsoleHost(ConsoleHost *host);
	static void patchProcess(void *processHandle);

	template<typename T>
	static void sendPacket(void *pipe, uint32_t op, T *data)
	{
		return sendPacket_(pipe, op, reinterpret_cast<uint8_t *>(data), sizeof(T));
	}
	static void sendPacket(void *pipe, uint32_t op)
	{
		return sendPacket_(pipe, op, nullptr, 0);
	}
};