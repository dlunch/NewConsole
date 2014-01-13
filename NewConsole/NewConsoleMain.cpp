#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "ConsoleHostServer.h"
#include "ConsoleHost.h"

LRESULT CALLBACK WndProc(HWND hWnd, UINT iMessage, WPARAM wParam, LPARAM lParam);

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	WNDCLASSEX wcex;
	ZeroMemory(&wcex, sizeof(wcex));
	wcex.cbSize = sizeof(wcex);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszClassName = TEXT("Console");
	wcex.lpfnWndProc = (WNDPROC)WndProc;
	wcex.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
	wcex.hCursor = LoadCursor(NULL, IDC_IBEAM);

	HWND hWnd = CreateWindowEx(WS_EX_OVERLAPPEDWINDOW, (LPCWSTR)RegisterClassEx(&wcex), TEXT("Console"), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, NULL, NULL);

	ShowWindow(hWnd, nShowCmd);

	ConsoleHostServer::initialize();
	ConsoleHost host(L"C:\\windows\\system32\\cmd.exe");

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

LRESULT CALLBACK WndProc(HWND hWnd, UINT iMessage, WPARAM wParam, LPARAM lParam)
{
	switch(iMessage)
	{
	case WM_CREATE:
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}
	return DefWindowProc(hWnd, iMessage, wParam, lParam);
}