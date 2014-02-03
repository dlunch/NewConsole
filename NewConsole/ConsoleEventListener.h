#pragma once

#include <cstdint>

class ConsoleEventListener
{
public:
	virtual void handleWrite(const std::string &buffer) = 0;
};