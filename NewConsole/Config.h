#pragma once

#include <cstdint>

class Config
{
public:
	static uint32_t getBackgroundColor()
	{
		return 0x70000000;
	}
	static bool useClearType()
	{
		return false;	
	}
};
