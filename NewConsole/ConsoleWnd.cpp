#include "ConsoleWnd.h"

#include "ConsoleHost.h"
#include "NewConsole.h"

ConsoleWnd::ConsoleWnd(const std::wstring &cmdline, NewConsole *mainWnd) : host_(new ConsoleHost(cmdline, this)), cacheWidth_(-1), cacheHeight_(-1), mainWnd_(mainWnd)
{
}

ConsoleWnd::~ConsoleWnd()
{
}

void ConsoleWnd::handleWrite(uint8_t *buffer, size_t size)
{
	buffer_.push_back(std::string(buffer, buffer + size));
	mainWnd_->contentsUpdated(this);
}

void ConsoleWnd::updateCache(int width, int height, int scrollx, int scrolly)
{
	if(cacheWidth_ != width || cacheHeight_ != height)
	{
		cacheBitmap_.reset(new Gdiplus::Bitmap(width, height, PixelFormat32bppARGB));
		cacheWidth_ = width;
		cacheHeight_ = height;
	}

	Gdiplus::Graphics g(cacheBitmap_.get());
	Gdiplus::Font font(L"Fixedsys", 10);
	Gdiplus::SolidBrush brush(Gdiplus::Color::Black);
	Gdiplus::RectF rect(0.f, 0.f, static_cast<float>(width), static_cast<float>(height));
	Gdiplus::StringFormat format(Gdiplus::StringFormatFlagsBypassGDI);

	auto it = buffer_.begin();
	size_t lines = static_cast<int>(height / font.GetHeight(&g));
	for(size_t c = lines - 1; c >= 0; c --)
	{
		wchar_t *buf;
		int len;

		len = MultiByteToWideChar(CP_UTF8, 0, it->c_str(), -1, nullptr, 0);
		buf = new wchar_t[len];
		MultiByteToWideChar(CP_UTF8, 0, it->c_str(), -1, buf, len);
		buf[len] = 0;

		g.DrawString(buf, len, &font, rect, &format, &brush);
		rect.Y += font.GetHeight(&g);

		delete [] buf;
	}
}

void ConsoleWnd::drawScreenContents(HDC hdc, int x, int y, int width, int height, int scrollx, int scrolly)
{
	if(scrolly != cacheScrolly_ || scrollx != cacheScrollx_ || width != cacheWidth_ || height != cacheHeight_)
		updateCache(width, height, scrollx, scrolly);

	Gdiplus::Graphics g(hdc);
	g.DrawImage(cacheBitmap_.get(), x, y);
}
