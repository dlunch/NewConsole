#pragma once

#include <cstdint>

class ConsoleEventListener
{
public:
	virtual void handleWrite(uint8_t *buffer, size_t size) = 0;
};