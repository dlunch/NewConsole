#pragma once

#include <memory>
#include <string>
#include <list>
#include <mutex>

#include <Windows.h>
#include <gdiplus.h>

#include "ConsoleEventListener.hpp"

class ConsoleHost;
class NewConsole;
class ConsoleWnd : public ConsoleEventListener, public std::enable_shared_from_this<ConsoleWnd>
{
private:
	std::shared_ptr<ConsoleHost> host_;

	std::shared_ptr<Gdiplus::Bitmap> cacheBitmap_;
	int cacheScrollx_;
	int cacheScrolly_;
	int cacheWidth_;
	int cacheHeight_;

	std::wstring inputBuffer_;
	std::list<std::pair<std::wstring, float>> buffer_;
	std::mutex bufferLock_;
	std::weak_ptr<NewConsole> mainWnd_;
private:
	virtual void handleWrite(const std::wstring &buffer);
	void updateCache(int width, int height, int scrollx, int scrolly);
	void invalidateCache();
	void bufferUpdated();
	void appendStringToBuffer(const std::wstring &buffer);
public:
	ConsoleWnd(const std::wstring &cmdline, std::weak_ptr<NewConsole> mainWnd);
	~ConsoleWnd();

	void drawScreenContents(HDC hdc, int x, int y, int width, int height, int scrollx, int scrolly);
	void appendInputBuffer(const std::wstring &buffer);
};
