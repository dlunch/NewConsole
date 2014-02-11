#pragma once

#include <Windows.h>
#include <memory>
#include <list>

class ConsoleWnd;
class NewConsole : public std::enable_shared_from_this<NewConsole>
{
private:
	HDC mainDC_;
	HBITMAP mainBitmap_;
	HANDLE mainThread_;
	HWND mainWnd_;
	ULONG_PTR gdiplusToken_;
	std::list<std::shared_ptr<ConsoleWnd>> consoles_;
	std::weak_ptr<ConsoleWnd> activeConsole_;
	bool redrawQueued_;
private:
	static void CALLBACK redrawCallback_(ULONG_PTR dwParam);
	void redrawCallback();
	static LRESULT CALLBACK WndProc_(HWND hWnd, UINT iMessage, WPARAM wParam, LPARAM lParam);
	LRESULT WndProc(UINT iMessage, WPARAM wParam, LPARAM lParam);
	void redraw();
public:
	NewConsole();
	~NewConsole();

	int run(int nShowCmd);
	void contentsUpdated(std::weak_ptr<ConsoleWnd> wnd);
	HWND gethWnd();
};
