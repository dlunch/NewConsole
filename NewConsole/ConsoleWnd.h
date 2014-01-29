#pragma once

#include <memory>
#include <string>
#include <list>

#include <Windows.h>
#include <gdiplus.h>

#include "ConsoleEventListener.h"

class ConsoleHost;
class NewConsole;
class ConsoleWnd : public ConsoleEventListener
{
private:
	std::shared_ptr<ConsoleHost> host_;

	std::shared_ptr<Gdiplus::Bitmap> cacheBitmap_;
	int cacheScrollx_;
	int cacheScrolly_;
	int cacheWidth_;
	int cacheHeight_;

	std::list<std::string> buffer_;
	NewConsole *mainWnd_;
private:
	virtual void handleWrite(uint8_t *buffer, size_t size);
	void updateCache(int width, int height, int scrollx, int scrolly);

public:
	ConsoleWnd(const std::wstring &cmdline, NewConsole *mainWnd);
	~ConsoleWnd();

	void drawScreenContents(HDC hdc, int x, int y, int width, int height, int scrollx, int scrolly);
};
