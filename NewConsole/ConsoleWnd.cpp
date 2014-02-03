#include "ConsoleWnd.h"

#include "ConsoleHost.h"
#include "NewConsole.h"

ConsoleWnd::ConsoleWnd(const std::wstring &cmdline, std::weak_ptr<NewConsole> mainWnd) : 
	host_(new ConsoleHost(cmdline, this)), cacheWidth_(-1), cacheHeight_(-1), mainWnd_(mainWnd), cacheScrollx_(-1), cacheScrolly_(-1)
{
}

ConsoleWnd::~ConsoleWnd()
{
}

void ConsoleWnd::appendStringToBuffer(const std::string &buffer)
{
	std::string line;
	int pos = 0;
	for(size_t i = 0; i < buffer.size(); i ++)
	{
		if(buffer[i] == '\n')
		{
			buffer_.push_back(line);

			line.clear();
			pos = 0;
		}
		else if(buffer[i] == '\r')
			pos = 0;
		else
		{
			if(pos + 1 > line.size())
				line.push_back(buffer[i]);
			else
				line[pos] = buffer[i];
			pos ++;
		}
	}
	if(line.size())
		buffer_.push_back(line);
	bufferUpdated();
}

void ConsoleWnd::handleWrite(uint8_t *buffer, size_t size)
{
	appendStringToBuffer(std::string(buffer, buffer + size));
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
	Gdiplus::Font font(L"Consolas", 10);
	Gdiplus::SolidBrush blackBrush(Gdiplus::Color::Black);
	Gdiplus::SolidBrush whiteBrush(Gdiplus::Color::White);
	Gdiplus::RectF rect(0.f, 0.f, static_cast<float>(width), static_cast<float>(height));
	Gdiplus::StringFormat format(Gdiplus::StringFormatFlagsBypassGDI);
	g.FillRectangle(&blackBrush, 0, 0, width, height);

	auto it = buffer_.begin();
	int lines = min(static_cast<int>(height / font.GetHeight(&g)), static_cast<int>(buffer_.size()));
	for(int c = lines - 1; c >= 0; c --)
	{
		wchar_t *buf;
		int len;

		len = MultiByteToWideChar(CP_UTF8, 0, it->c_str(), -1, nullptr, 0);
		buf = new wchar_t[len + 1];
		MultiByteToWideChar(CP_UTF8, 0, it->c_str(), -1, buf, len);
		buf[len] = 0;

		Gdiplus::RectF bound;
		g.MeasureString(buf, len, &font, rect, &format, &bound);
		g.DrawString(buf, len, &font, rect, &format, &whiteBrush);
		rect.Y += bound.Height;

		delete [] buf;
		it ++;
	}
}

void ConsoleWnd::drawScreenContents(HDC hdc, int x, int y, int width, int height, int scrollx, int scrolly)
{
	if(scrolly != cacheScrolly_ || scrollx != cacheScrollx_ || width != cacheWidth_ || height != cacheHeight_)
		updateCache(width, height, scrollx, scrolly);

	Gdiplus::Graphics g(hdc);
	g.DrawImage(cacheBitmap_.get(), x, y);
}

void ConsoleWnd::appendInputBuffer(const std::string &buffer)
{
	std::string lastLine = *buffer_.rbegin();
	buffer_.pop_back();
	lastLine += buffer;
	inputBuffer_ += buffer;

	appendStringToBuffer(lastLine);

	if(buffer[buffer.size() - 1] == '\n')
	{
		inputBuffer_.pop_back();
		inputBuffer_ += "\r\n";
		host_->write(inputBuffer_);
		inputBuffer_.clear();
	}
}

void ConsoleWnd::bufferUpdated()
{
	invalidateCache();
	if(!mainWnd_.expired())
		mainWnd_.lock()->contentsUpdated(shared_from_this());
}

void ConsoleWnd::invalidateCache()
{
	cacheScrollx_ = -1;
}