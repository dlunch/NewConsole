#include "NewConsole.h"
#include <gdiplus.h>

#include "ConsoleHostServer.h"
#include "ConsoleWnd.h"

#pragma comment(lib, "gdiplus.lib")

NewConsole::NewConsole() : mainDC_(CreateCompatibleDC(nullptr)), mainBitmap_(nullptr)
{
	Gdiplus::GdiplusStartupInput gdiplusStartupInput;
	Gdiplus::GdiplusStartup(&gdiplusToken_, &gdiplusStartupInput, nullptr);

	ConsoleHostServer::initialize();
}

NewConsole::~NewConsole()
{
	Gdiplus::GdiplusShutdown(gdiplusToken_);

	DeleteDC(mainDC_);
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
	RECT rt;
	GetWindowRect(mainWnd_, &rt);
	int width = rt.right - rt.left;
	int height = rt.bottom - rt.top;
	if(!mainBitmap_)
		mainBitmap_ = CreateCompatibleBitmap(mainDC_, width, height);
	SelectObject(mainDC_, mainBitmap_);
	
	wnd->drawScreenContents(mainDC_, 0, 0, width, height, 0, 0);

	BLENDFUNCTION bf;
	bf.AlphaFormat = AC_SRC_ALPHA;
	bf.BlendFlags = 0;
	bf.BlendOp = AC_SRC_OVER;
	bf.SourceConstantAlpha = 255;

	UpdateLayeredWindow(mainWnd_, nullptr, nullptr, nullptr, mainDC_, nullptr, 0, &bf, ULW_ALPHA);
}

LRESULT NewConsole::WndProc(UINT iMessage, WPARAM wParam, LPARAM lParam)
{
	switch(iMessage)
	{
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	case WM_SIZE:
		if(mainBitmap_)
			DeleteObject(mainBitmap_);
		mainBitmap_ = nullptr;
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
		SetWindowLongPtr(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this_));
	}
	else
		this_ = reinterpret_cast<NewConsole *>(GetWindowLongPtr(hWnd, GWLP_USERDATA));
	if(this_)
		return this_->WndProc(iMessage, wParam, lParam);
	return DefWindowProc(hWnd, iMessage, wParam, lParam);
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	NewConsole instance;
	return instance.run(nShowCmd);	
}
