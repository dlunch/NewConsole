#pragma once

class Patcher
{
public:
	static void initPatch();
	static void patchProcess(void *processHandle);
};
