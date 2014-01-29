#include "NewConsole.h"
#include <gdiplus.h>

#include "ConsoleHostServer.h"
#include "ConsoleWnd.h"

#pragma comment(lib, "gdiplus.lib")

NewConsole::NewConsole()
{
	Gdiplus::GdiplusStartupInput gdiplusStartupInput;
	Gdiplus::GdiplusStartup(&gdiplusToken_, &gdiplusStartupInput, nullptr);

	ConsoleHostServer::initialize();
}

NewConsole::~NewConsole()
{
	Gdiplus::GdiplusShutdown(gdiplusToken_);
}

int NewConsole::run(int nShowCmd)
{
	WNDCLASSEX wcex;
	ZeroMemory(&wcex, sizeof(wcex));
	wcex.cbSize = sizeof(wcex);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszClassName = TEXT("Console");
	wcex.lpfnWndProc = (WNDPROC)&NewConsole::WndProc_;
	wcex.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
	wcex.hCursor = LoadCursor(NULL, IDC_IBEAM);

	mainWnd_ = CreateWindowEx(WS_EX_OVERLAPPEDWINDOW | WS_EX_LAYERED, (LPCWSTR)RegisterClassEx(&wcex), TEXT("Console"), 
							   WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, NULL, this);

	ShowWindow(mainWnd_, nShowCmd);

	ConsoleWnd wnd(L"C:\\windows\\system32\\cmd.exe", this);

	MSG msg;
	while(true)
	{
		MsgWaitForMultipleObjectsEx(0, nullptr, INFINITE, QS_ALLEVENTS, MWMO_ALERTABLE);
		while(PeekMessage(&msg, 0, 0, 0, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
			if(msg.message == WM_QUIT)
				break;
		}
		if(msg.message == WM_QUIT)
			break;
	}

	return 0;
}

void NewConsole::contentsUpdated(ConsoleWnd *wnd)
{
	
}

LRESULT NewConsole::WndProc(UINT iMessage, WPARAM wParam, LPARAM lParam)
{
	switch(iMessage)
	{
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProc(mainWnd_, iMessage, wParam, lParam);
}

LRESULT CALLBACK NewConsole::WndProc_(HWND hWnd, UINT iMessage, WPARAM wParam, LPARAM lParam)
{
	NewConsole *this_ = nullptr;
	if(iMessage == WM_NCCREATE)
	{
		CREATESTRUCT *cs = reinterpret_cast<CREATESTRUCT *>(lParam);
		this_ = reinterpret_cast<NewConsole *>(cs->lpCreateParams);
		this_->mainWnd_ = hWnd;
		SetWindowLongPtr(hWnd, GWLP_USERDATA, reinterpret_cast<LONG>(this_));
	}
	else
		this_ = reinterpret_cast<NewConsole *>(GetWindowLongPtr(hWnd, GWLP_USERDATA));
	return this_->WndProc(iMessage, wParam, lParam);
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	NewConsole instance;
	return instance.run(nShowCmd);	
}
