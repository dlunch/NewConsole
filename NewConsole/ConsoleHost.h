#pragma once

#include <cstdint>
#include <string>

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

	void cleanup();
	uint8_t *getInputBuffer(size_t requestSize, size_t *resultSize);
	void handleWrite(uint8_t *buffer, size_t bufferSize);
public:
	ConsoleHost(const std::wstring &process);
	~ConsoleHost();

	void writeToConsole(const std::wstring &string);
	void handlePacket(uint16_t op, uint32_t size, uint8_t *data);
	void handleDisconnected();
	void setConnection(ConsoleHostConnection *connection);
};