#pragma once

#include <cstdint>
#include <string>

class ConsoleHostConnection;
class ConsoleHost
{
	friend class ConsoleHostServer;
private:
	void *childProcess_;
	uint32_t childProcessId_;

	void cleanup();
public:
	ConsoleHost(const std::wstring &process);
	~ConsoleHost();

	void writeToConsole(const std::wstring &string);
	void handlePacket(ConsoleHostConnection *connection, uint16_t op, uint32_t size, uint8_t *data);
	void handleDisconnected(ConsoleHostConnection *connection);
};