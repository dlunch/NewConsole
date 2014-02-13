#pragma once

class Patcher
{
public:
	static void initPatch();
	static bool patchProcess(void *processHandle);
};
