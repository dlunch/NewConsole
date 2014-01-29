#pragma once

#include <Windows.h>

class ConsoleWnd;
class NewConsole
{
private:
	HDC mainDC_;
	HBITMAP mainBitmap_;
	HWND mainWnd_;
	ULONG_PTR gdiplusToken_;
private:
	static LRESULT CALLBACK WndProc_(HWND hWnd, UINT iMessage, WPARAM wParam, LPARAM lParam);
	LRESULT WndProc(UINT iMessage, WPARAM wParam, LPARAM lParam);
public:
	NewConsole();
	~NewConsole();

	int run(int nShowCmd);
	void contentsUpdated(ConsoleWnd *wnd);
};
