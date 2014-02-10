#pragma once

#include <cstdint>

class ConsoleEventListener
{
public:
	virtual void handleWrite(const std::wstring &buffer) = 0;
};