#pragma once

#include <cstdint>
#include <memory>

class ConsoleHost;
class ConsoleEventListener
{
public:
	virtual void handleWrite(const std::wstring &buffer) = 0;
	virtual void handleRead(size_t size) = 0;
};