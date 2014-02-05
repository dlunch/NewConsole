#pragma once

#include <cstdint>
#include <string>
#include <functional>
#include <list>

class ConsoleEventListener;
class ConsoleHostConnection;
class ConsoleHost
{
	friend class ConsoleHostServer;
private:
	int inputMode_;
	int outputMode_;
	void *childProcess_;
	uint32_t childProcessId_;
	ConsoleHostConnection *connection_;
	ConsoleEventListener *listener_;
	std::string inputBuffer_;
	int lastHandleId_;
	std::list<void *> inputHandles_;
	std::list<void *> outputHandles_;
	std::list<void *> serverHandles_;

	std::list<std::tuple<size_t, std::function<void (const uint8_t *, size_t, size_t, void *)>, bool, void *>> queuedReadOperations_;

	void *newFakeHandle();
	void cleanup();
	void queueReadOperation(size_t size, const std::function<void (const uint8_t *, size_t, size_t, void *)> &completion, bool isWidechar, void *userData);
	void checkQueuedRead();
	void handleWrite(uint8_t *buffer, size_t bufferSize);
	bool isInputHandle(void *handle);
	bool isOutputHandle(void *handle);
	void sendNewConsoleAPIResponse(void *responsePtr, void *buffer, size_t bufferSize);
	template<typename T>
	void sendNewConsoleAPIResponse(void *responsePtr, T data)
	{
		return sendNewConsoleAPIResponse(responsePtr, &data, sizeof(T));
	}
public:
	ConsoleHost(const std::wstring &cmdline, ConsoleEventListener *listener);
	~ConsoleHost();

	void write(const std::string &buffer);
	void handlePacket(uint16_t op, uint32_t size, uint8_t *data);
	void handleDisconnected();
	void setConnection(ConsoleHostConnection *connection);
};