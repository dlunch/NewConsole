#pragma once

#include <cstdint>
#include <string>

class ConsoleHost
{
	friend class ConsoleHostServer;
private:
	void *childProcess_;
	uint32_t childProcessId_;

	void handlePacket(void *fromPipe, uint16_t op, uint32_t length, uint8_t *data);
	void handleDisconnected();
	void cleanup();
public:
	ConsoleHost(const std::wstring &process);
	~ConsoleHost();

	void writeToConsole(const std::wstring &string);
};